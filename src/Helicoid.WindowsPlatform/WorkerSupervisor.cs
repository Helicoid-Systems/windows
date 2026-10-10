using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform.Native;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Configuration for the worker supervisor. Timing values are validated at
/// construction: every duration must be positive and bounded, and
/// <see cref="HeartbeatTimeout"/> must strictly exceed
/// <see cref="HeartbeatInterval"/> so scheduling jitter cannot manufacture a
/// liveness failure.
/// </summary>
public sealed record SupervisorConfig
{
    /// <summary>Upper bound on any configured duration (1 hour).</summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromHours(1);

    /// <summary>Path to the worker executable.</summary>
    public required string WorkerExecutablePath { get; init; }

    /// <summary>Maximum time to wait for worker to connect via IPC.</summary>
    public required TimeSpan WorkerConnectTimeout { get; init; }

    /// <summary>Maximum worker lifetime before forced restart.</summary>
    public required TimeSpan WorkerMaxLifetime { get; init; }

    /// <summary>Heartbeat interval for liveness checks.</summary>
    public required TimeSpan HeartbeatInterval { get; init; }

    /// <summary>Maximum consecutive worker failures before giving up.</summary>
    public required int MaxConsecutiveFailures { get; init; }

    /// <summary>Delay before restarting after a failure.</summary>
    public required TimeSpan RestartDelay { get; init; }

    /// <summary>
    /// Maximum time to wait for a heartbeat response before the worker is
    /// treated as dead. Bounds liveness so a hung worker cannot linger.
    /// Must be strictly greater than <see cref="HeartbeatInterval"/>.
    /// </summary>
    public required TimeSpan HeartbeatTimeout { get; init; }

    /// <summary>
    /// Optional starting desktop generation. Defaults to
    /// <see cref="DesktopGeneration.Initial"/>. Tests may start near
    /// <see cref="DesktopGeneration.MaxValue"/> to exercise exhaustion.
    /// </summary>
    public uint InitialGeneration { get; init; } = DesktopGeneration.Initial;

    /// <summary>
    /// Validate positive bounded timing. Throws
    /// <see cref="ArgumentOutOfRangeException"/> on zero/negative/oversized
    /// durations or when the heartbeat timeout does not exceed the interval.
    /// </summary>
    public void ValidateTiming()
    {
        ValidatePositiveBounded(WorkerConnectTimeout, nameof(WorkerConnectTimeout));
        ValidatePositiveBounded(WorkerMaxLifetime, nameof(WorkerMaxLifetime));
        ValidatePositiveBounded(HeartbeatInterval, nameof(HeartbeatInterval));
        ValidatePositiveBounded(HeartbeatTimeout, nameof(HeartbeatTimeout));
        ValidatePositiveBounded(RestartDelay, nameof(RestartDelay));

        if (MaxConsecutiveFailures < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxConsecutiveFailures), "Must be at least 1.");
        }

        if (HeartbeatTimeout <= HeartbeatInterval)
        {
            throw new ArgumentOutOfRangeException(
                nameof(HeartbeatTimeout),
                "Heartbeat timeout must strictly exceed the heartbeat interval so scheduling jitter cannot manufacture a liveness failure.");
        }
    }

    private static void ValidatePositiveBounded(TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(name, "Duration must be positive.");
        }

        if (value > MaxDuration)
        {
            throw new ArgumentOutOfRangeException(name, $"Duration must not exceed {MaxDuration}.");
        }
    }
}

/// <summary>
/// Manages the lifecycle of a child worker process. Creates a Job Object
/// with KILL_ON_JOB_CLOSE, launches the worker with atomic job assignment
/// via STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_JOB_LIST, authenticates via IPC,
/// and tracks desktop generation invalidation on lock/logout/user switch.
///
/// Start path:
/// 1. Generate capability nonce and fencing IDs (boot + launch)
/// 2. Create named pipe server (before child launch)
/// 3. Create Job Object with KILL_ON_JOB_CLOSE
/// 4. Create child process with PROC_THREAD_ATTRIBUTE_JOB_LIST (atomic job bind)
/// 5. Wait for authenticated IPC handshake from child
/// 6. Verify kernel PID, session, token SID, capability nonce, and fence IDs
///
/// Fencing: every async callback captures (bootId, launchId, generation) at
/// schedule time and re-checks them before acting. Worker disconnect/crash and
/// lock/logoff/console replacement invalidate the current work; a stale
/// callback can never act on a replacement worker.
///
/// Survives worker crashes: stops generation-scoped work and records named
/// unavailable status. Cleanup never depends on worker callback or audit success.
/// </summary>
public sealed class WorkerSupervisor : IDisposable
{
    private readonly SupervisorConfig _config;
    private readonly byte[] _bootId = FencingIds.GenerateId();
    private readonly object _lock = new();
    private KillOnCloseJob? _job;
    private SafeProcessHandle? _childProcessHandle;
    private uint _childProcessId;
    private Process? _workerProcess;
    private SupervisorIpcChannel? _ipcChannel;
    private WorkerIdentity? _currentWorker;
    private DesktopGeneration _generation;
    private WorkerStatus _workerStatus = WorkerStatus.NotStarted;
    private SupervisorStatus _status = SupervisorStatus.Idle;
    private int _consecutiveFailures;
    private bool _disposed;
    private bool _generationExhausted;
    private CancellationTokenSource? _lifetimeCts;
    private Task? _lifetimeTask;
    private CancellationTokenSource? _heartbeatCts;
    private Task? _heartbeatTask;

    public WorkerSupervisor(SupervisorConfig config)
    {
        config.ValidateTiming();
        _config = config;
        _generation = new DesktopGeneration { Value = config.InitialGeneration };
    }

    /// <summary>
    /// True once <see cref="Dispose"/> has run. Delayed startup work must check
    /// this and fail quietly rather than launch a worker after disposal.
    /// </summary>
    public bool IsDisposed
    {
        get { lock (_lock) return _disposed; }
    }

    /// <summary>
    /// The boot ID for this supervisor instance. Persists across worker restarts.
    /// Old callbacks from a previous supervisor process are rejected.
    /// Returns a defensive copy — callers cannot mutate the active fence.
    /// </summary>
    public byte[] BootId => (byte[])_bootId.Clone();

    /// <summary>
    /// Check if a callback's boot ID matches this supervisor. Zero or
    /// malformed IDs never match.
    /// </summary>
    public bool IsCurrentBoot(byte[]? callbackBootId)
    {
        if (!FencingIds.IsUsableId(_bootId) || !FencingIds.IsUsableId(callbackBootId)) return false;
        int diff = 0;
        for (int i = 0; i < FencingIds.IdLength; i++) diff |= _bootId[i] ^ callbackBootId![i];
        return diff == 0;
    }

    /// <summary>Current supervisor status.</summary>
    public SupervisorStatus Status
    {
        get { lock (_lock) return _status; }
    }

    /// <summary>Current worker status.</summary>
    public WorkerStatus WorkerStatus
    {
        get { lock (_lock) return _workerStatus; }
    }

    /// <summary>Current desktop generation.</summary>
    public DesktopGeneration Generation
    {
        get { lock (_lock) return _generation; }
    }

    /// <summary>Current worker identity, if any. Launch ID is a defensive copy.</summary>
    public WorkerIdentity? CurrentWorker
    {
        get
        {
            lock (_lock)
            {
                return _currentWorker is { } worker
                    ? worker with { LaunchId = (byte[])worker.LaunchId.Clone() }
                    : null;
            }
        }
    }

    /// <summary>Consecutive failure count.</summary>
    public int ConsecutiveFailures
    {
        get { lock (_lock) return _consecutiveFailures; }
    }

    /// <summary>
    /// True once the desktop generation counter is exhausted. No further
    /// worker may be started; generations never wrap or reuse.
    /// </summary>
    public bool IsGenerationExhausted
    {
        get { lock (_lock) return _generationExhausted; }
    }

    /// <summary>
    /// Start a worker process. The supervisor:
    /// 1. Creates the named pipe server BEFORE launching the child
    /// 2. Creates a Job Object with KILL_ON_JOB_CLOSE
    /// 3. Launches the child with PROC_THREAD_ATTRIBUTE_JOB_LIST (atomic job bind)
    /// 4. Passes capability + pipe name + fencing IDs via private environment variables
    /// 5. Waits for authenticated IPC handshake
    /// 6. Verifies kernel PID, session, token SID, capability nonce, and fences
    ///
    /// Returns true if the worker started and authenticated successfully.
    /// Disposal-before-start and generation exhaustion fail quietly without
    /// launching a worker.
    /// </summary>
    public bool TryStartWorker()
    {
        // Disposal-before-start (including delayed Task.Run startup) fails
        // quietly and does not launch a worker.
        lock (_lock)
        {
            if (_disposed || _generationExhausted)
            {
                return false;
            }

            if (_workerStatus is not (WorkerStatus.NotStarted or WorkerStatus.Exited or WorkerStatus.Failed or WorkerStatus.Killed))
            {
                return false;
            }

            _status = SupervisorStatus.StartingWorker;
            _workerStatus = WorkerStatus.Starting;
        }

        try
        {
            // Step 1: Generate capability nonce for this launch.
            var capability = LaunchCapability.Generate();

            // Step 1b: Generate fresh launch ID. Boot ID already exists for this supervisor.
            byte[] launchId = FencingIds.GenerateId();
            if (!FencingIds.IsUsableId(_bootId) || !FencingIds.IsUsableId(launchId))
            {
                HandleWorkerFailure("Fencing IDs are not usable");
                return false;
            }

            var fence = new FencingIds { BootId = _bootId, LaunchId = launchId };

            // Step 2: Capture our own kernel identity for mutual verification.
            // The child is launched in our session under our token, so these are
            // the expected child identity values.
            uint supervisorPid = Kernel32Native.GetCurrentProcessId();
            if (!WtsNative.ProcessIdToSessionId(supervisorPid, out uint supervisorSessionId))
            {
                HandleWorkerFailure("Failed to resolve supervisor session identity");
                return false;
            }

            string? supervisorSid = GetCurrentProcessTokenSid();
            if (string.IsNullOrEmpty(supervisorSid))
            {
                HandleWorkerFailure("Failed to resolve supervisor token identity");
                return false;
            }

            uint currentGeneration;
            lock (_lock)
            {
                currentGeneration = _generation.Value;
            }

            // Step 3: Create Job Object BEFORE child launch.
            _job?.Dispose();
            _job = new KillOnCloseJob();

            // Step 4: Create IPC channel (creates pipe server BEFORE child launch).
            _ipcChannel?.Dispose();
            _ipcChannel = new SupervisorIpcChannel(
                capability,
                0, // PID not known yet; will verify from pipe client
                supervisorSessionId,
                supervisorSid!,
                fence,
                currentGeneration);

            // Step 5: Launch child process with atomic job assignment.
            // Pass capability, pipe name, IDs via private environment variables.
            string envCapability = Convert.ToHexString(capability.Bytes);
            string envPipeName = _ipcChannel.PipeName;
            string envGeneration = currentGeneration.ToString();
            string envBootId = Convert.ToHexString(_bootId);
            string envLaunchId = Convert.ToHexString(launchId);

            if (!TryLaunchChildWithJobList(
                envCapability,
                envPipeName,
                envGeneration,
                envBootId,
                envLaunchId,
                out var processHandle,
                out uint childPid))
            {
                HandleWorkerFailure("Failed to launch worker process with job list");
                return false;
            }

            // Hold the process handle securely.
            _childProcessHandle = processHandle;
            _childProcessId = childPid;

            // Step 6: Bind actual child PID to the SAME IPC channel (same pipe server).
            // The pipe was created before launch; we now tell it which PID to expect.
            _ipcChannel.BindExpectedPid(childPid);

            // Also create a Process object for lifecycle monitoring (does not own the handle).
            try
            {
                _workerProcess = Process.GetProcessById((int)childPid);
            }
            catch (Exception)
            {
                // Process may have exited already; will be caught by IPC timeout.
            }

            lock (_lock)
            {
                _currentWorker = new WorkerIdentity
                {
                    ProcessId = childPid,
                    SessionId = supervisorSessionId,
                    TokenSid = supervisorSid!,
                    Generation = new DesktopGeneration { Value = currentGeneration },
                    StartedAt = DateTimeOffset.UtcNow,
                    LaunchId = launchId,
                };
            }

            var authResult = _ipcChannel.WaitForAuthenticatedConnection(
                _config.WorkerConnectTimeout);

            if (authResult != IpcAuthenticationResult.Authenticated)
            {
                HandleWorkerFailure($"Worker authentication failed: {authResult}");
                return false;
            }

            // Fenced identity check: the worker we just authenticated must still
            // be the current one. A concurrent lock/logoff may have fenced it.
            if (!IsCurrentLaunch(launchId, currentGeneration))
            {
                CleanupWorkerProcess();
                return false;
            }

            lock (_lock)
            {
                _workerStatus = WorkerStatus.Connected;
                _status = SupervisorStatus.WorkerRunning;
                _consecutiveFailures = 0;
            }

            // Start lifetime and heartbeat monitoring, both fenced.
            StartLifetimeMonitor(launchId, currentGeneration);
            StartHeartbeatMonitor(launchId, currentGeneration);

            return true;
        }
        catch (Exception)
        {
            HandleWorkerFailure("Exception during worker start");
            return false;
        }
    }

    /// <summary>
    /// Invalidate the current desktop generation. Called on lock/logout/user
    /// switch. Stops generation-scoped work and prepares for a new generation.
    /// Any in-flight callback from the previous generation is fenced out.
    /// Generation exhaustion fences and blocks restart — never wraps.
    /// </summary>
    public void InvalidateGeneration(string reason)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        lock (_lock)
        {
            if (_generationExhausted || !_generation.TryNext(out var next))
            {
                // Exhausted: fence everything and block restart permanently.
                _generation = new DesktopGeneration { Value = DesktopGeneration.MaxValue };
                _status = SupervisorStatus.GenerationInvalidated;
                _currentWorker = null;
                _generationExhausted = true;
            }
            else
            {
                _generation = next;
                _status = SupervisorStatus.GenerationInvalidated;
                _currentWorker = null;
            }
        }

        StopWorker(reason);
    }

    /// <summary>
    /// Stop the current worker process. The worker is terminated via the
    /// Job Object (if still running) or gracefully via IPC shutdown message.
    /// </summary>
    public void StopWorker(string reason)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        StopLifetimeMonitor();
        StopHeartbeatMonitor();

        lock (_lock)
        {
            if (_workerStatus is WorkerStatus.NotStarted or WorkerStatus.Exited)
            {
                return;
            }

            _workerStatus = WorkerStatus.ShuttingDown;
        }

        // Try graceful shutdown via IPC first. Fence stamp is mandatory.
        try
        {
            if (_ipcChannel is not null)
            {
                var fence = _ipcChannel.CreateFenceStamp();
                _ipcChannel.TrySendMessage(
                    new IpcMessage { Type = IpcMessageType.Shutdown, Payload = fence.Serialize() },
                    TimeSpan.FromSeconds(2));
            }
        }
        catch (Exception)
        {
            // Graceful shutdown failed; will be killed by Job Object.
        }

        // Wait briefly for graceful exit.
        if (_workerProcess is not null && !_workerProcess.HasExited)
        {
            if (!_workerProcess.WaitForExit(2000))
            {
                // Force terminate via process handle.
                if (_childProcessHandle is not null && !_childProcessHandle.IsInvalid)
                {
                    ProcessNative.TerminateProcess(_childProcessHandle.DangerousGetHandle(), 1);
                }
            }
        }

        lock (_lock)
        {
            _workerStatus = WorkerStatus.Exited;
            _currentWorker = null;
        }

        CleanupWorkerProcess();
    }

    /// <summary>
    /// Notify the supervisor that the session was locked. This invalidates
    /// the current generation and stops the worker.
    /// </summary>
    public void OnSessionLocked()
    {
        InvalidateGeneration("Session locked");
    }

    /// <summary>
    /// Notify the supervisor that the session was unlocked. A new generation
    /// begins; the supervisor can start a new worker if enrolled. In-flight
    /// callbacks from the previous generation remain fenced out. Generation
    /// exhaustion blocks any new generation — never wraps or reuses.
    /// </summary>
    public void OnSessionUnlocked()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        lock (_lock)
        {
            if (_generationExhausted || !_generation.TryNext(out var next))
            {
                _generation = new DesktopGeneration { Value = DesktopGeneration.MaxValue };
                _status = SupervisorStatus.GenerationInvalidated;
                _workerStatus = WorkerStatus.NotStarted;
                _currentWorker = null;
                _generationExhausted = true;
                return;
            }

            _generation = next;
            _status = SupervisorStatus.Idle;
            _workerStatus = WorkerStatus.NotStarted;
            _currentWorker = null;
        }
    }

    /// <summary>
    /// Notify the supervisor that the physical console was replaced
    /// (e.g. user switch). Fences the current generation like a lock.
    /// </summary>
    public void OnConsoleReplaced()
    {
        InvalidateGeneration("Console replaced");
    }

    /// <summary>
    /// Returns true when the given launch ID and generation still identify the
    /// live worker. Used by every async callback before it acts. Zero or
    /// malformed IDs never match — no state change on invalid input.
    /// </summary>
    public bool IsCurrentLaunch(byte[]? launchId, uint generation)
    {
        if (!IsUsableId(launchId))
        {
            return false;
        }

        lock (_lock)
        {
            return _currentWorker is { } worker
                && IsUsableId(worker.LaunchId)
                && worker.Generation.Value == generation
                && _generation.Value == generation
                && FencingIdsEquals(worker.LaunchId!, launchId!);
        }
    }

    /// <summary>
    /// An ID is usable only when it is exactly <see cref="FencingIds.IdLength"/>
    /// bytes and not all-zero (a zero ID is never a real generated fence).
    /// </summary>
    private static bool IsUsableId(byte[]? id)
    {
        if (id is null || id.Length != FencingIds.IdLength)
        {
            return false;
        }

        int acc = 0;
        for (int i = 0; i < id.Length; i++)
        {
            acc |= id[i];
        }

        return acc != 0;
    }

    private static bool FencingIdsEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    /// <summary>
    /// Launch the child process with PROC_THREAD_ATTRIBUTE_JOB_LIST for atomic
    /// job assignment at creation time. This eliminates the race between
    /// Process.Start and AssignProcessToJobObject.
    ///
    /// Capability, pipe name, and fencing IDs are passed via private environment
    /// variables (not argv or public logs).
    /// </summary>
    private bool TryLaunchChildWithJobList(
        string capabilityHex,
        string pipeName,
        string generation,
        string bootId,
        string launchId,
        out SafeProcessHandle processHandle,
        out uint childPid)
    {
        processHandle = new SafeProcessHandle();
        childPid = 0;

        // Build environment block with private variables.
        // The child reads these and immediately erases them.
        string envBlock = BuildEnvironmentBlock(capabilityHex, pipeName, generation, bootId, launchId);

        // Initialize STARTUPINFOEX with job list attribute.
        var startupInfo = new STARTUPINFOEXW();
        startupInfo.StartupInfo.dwFlags = ProcessNative.StartfUseStdHandles;
        startupInfo.StartupInfo.hStdInput = IntPtr.Zero;
        startupInfo.StartupInfo.hStdOutput = IntPtr.Zero;
        startupInfo.StartupInfo.hStdError = IntPtr.Zero;

        // Allocate attribute list for 1 attribute (job list).
        UIntPtr attrListSize = UIntPtr.Zero;
        ProcessNative.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrListSize);

        IntPtr attrListBuffer = Marshal.AllocHGlobal((int)attrListSize);
        try
        {
            if (!ProcessNative.InitializeProcThreadAttributeList(attrListBuffer, 1, 0, ref attrListSize))
            {
                return false;
            }

            startupInfo.lpAttributeList = attrListBuffer;

            // Add PROC_THREAD_ATTRIBUTE_JOB_LIST with the job handle.
            if (_job is null)
            {
                return false;
            }

            // Get the job handle value from the SafeJobHandle.
            IntPtr jobHandle = _job.DangerousGetHandle();
            if (jobHandle == IntPtr.Zero)
            {
                return false;
            }

            if (!ProcessNative.UpdateProcThreadAttribute(
                attrListBuffer,
                0,
                (UIntPtr)ProcessNative.ProcThreadAttributeJobList,
                jobHandle,
                (UIntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero))
            {
                return false;
            }

            // Create the process.
            uint creationFlags = ProcessNative.ExtendedStartupinfoPresent
                | ProcessNative.CreateNoWindow
                | ProcessNative.CreateUnicodeEnvironment;

            // Pin the environment block.
            GCHandle envHandle = GCHandle.Alloc(System.Text.Encoding.Unicode.GetBytes(envBlock), GCHandleType.Pinned);
            try
            {
                string commandLine = $"\"{_config.WorkerExecutablePath}\"";

                if (!ProcessNative.CreateProcessW(
                    null,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false, // bInheritHandles — we pass via env, not inherited handles
                    creationFlags,
                    envHandle.AddrOfPinnedObject(),
                    null,
                    ref startupInfo,
                    out PROCESS_INFORMATION pi))
                {
                    return false;
                }

                // Close the thread handle (we don't need it).
                Kernel32Native.CloseHandle(pi.hThread);

                processHandle = new SafeProcessHandle(pi.hProcess);
                childPid = pi.dwProcessId;
                return true;
            }
            finally
            {
                envHandle.Free();
            }
        }
        finally
        {
            if (startupInfo.lpAttributeList != IntPtr.Zero)
            {
                ProcessNative.DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
                Marshal.FreeHGlobal(attrListBuffer);
            }
        }
    }

    /// <summary>
    /// Build a Unicode environment block with private variables.
    /// Format: null-terminated key=value pairs, double-null terminated.
    /// </summary>
    private static string BuildEnvironmentBlock(
        string capability, string pipeName, string generation, string bootId, string launchId)
    {
        // Standard environment variables from current process, plus private worker vars.
        var sb = new System.Text.StringBuilder();

        // Copy existing environment (excluding our private vars).
        foreach (var kvp in Environment.GetEnvironmentVariables())
        {
            var entry = (System.Collections.DictionaryEntry)kvp;
            string key = entry.Key?.ToString() ?? "";
            if (key.StartsWith("HELI_WORKER_", StringComparison.Ordinal))
            {
                continue; // Skip our private vars from parent env.
            }
            sb.Append(key);
            sb.Append('=');
            sb.Append(entry.Value?.ToString() ?? "");
            sb.Append('\0');
        }

        // Add our private variables.
        sb.Append($"HELI_WORKER_CAP={capability}");
        sb.Append('\0');
        sb.Append($"HELI_WORKER_PIPE={pipeName}");
        sb.Append('\0');
        sb.Append($"HELI_WORKER_GEN={generation}");
        sb.Append('\0');
        sb.Append($"HELI_WORKER_BOOT={bootId}");
        sb.Append('\0');
        sb.Append($"HELI_WORKER_LAUNCH={launchId}");
        sb.Append('\0');

        // Double-null terminate.
        sb.Append('\0');

        return sb.ToString();
    }

    /// <summary>
    /// Fence-aware failure handler. The callback captures launch/generation at
    /// schedule time; if the worker was replaced in the meantime, this is a no-op.
    /// </summary>
    private void HandleWorkerFailureFenced(string description, byte[] launchId, uint generation)
    {
        // Drop out if this callback is stale.
        if (!IsCurrentLaunch(launchId, generation))
        {
            return;
        }

        HandleWorkerFailure(description);
    }

    private void HandleWorkerFailure(string description)
    {
        StopLifetimeMonitor();
        StopHeartbeatMonitor();

        lock (_lock)
        {
            _consecutiveFailures++;
            _workerStatus = WorkerStatus.Failed;
            _status = SupervisorStatus.WorkerFailed;
            _currentWorker = null;
        }

        CleanupWorkerProcess();
    }

    private void CleanupWorkerProcess()
    {
        try
        {
            _ipcChannel?.Dispose();
            _ipcChannel = null;

            _workerProcess?.Dispose();
            _workerProcess = null;

            _childProcessHandle?.Dispose();
            _childProcessHandle = null;
            _childProcessId = 0;
        }
        catch (Exception)
        {
            // Cleanup must not throw.
        }
    }

    private void StartLifetimeMonitor(byte[] launchId, uint generation)
    {
        StopLifetimeMonitor();

        var cts = new CancellationTokenSource();
        _lifetimeCts = cts;
        _lifetimeTask = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(_config.WorkerMaxLifetime, cts.Token).ConfigureAwait(false);
                // Lifetime expired — fenced so a replaced worker is untouched.
                HandleWorkerFailureFenced("Worker lifetime exceeded", launchId, generation);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown — not a failure.
            }
            finally
            {
                // Dispose the CTS after the task completes (not before).
                cts.Dispose();
            }
        });
    }

    private void StopLifetimeMonitor()
    {
        // Capture and null the CTS reference, then cancel.
        // The task disposes the CTS in its finally block.
        var cts = _lifetimeCts;
        _lifetimeCts = null;
        _lifetimeTask = null;

        cts?.Cancel();

        // No .Wait() — the task will self-terminate from the cancellation.
        // The CTS is disposed by the task's finally block.
    }

    /// <summary>
    /// Bounded liveness monitor. Sends HeartbeatPing on the configured interval
    /// and requires a matching HeartbeatPong before the timeout elapses. A
    /// missing or late pong fails the worker; a stale callback cannot touch a
    /// replacement launch.
    /// </summary>
    private void StartHeartbeatMonitor(byte[] launchId, uint generation)
    {
        StopHeartbeatMonitor();

        var cts = new CancellationTokenSource();
        _heartbeatCts = cts;
        _heartbeatTask = Task.Run(async () =>
        {
            try
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(_config.HeartbeatInterval, cts.Token).ConfigureAwait(false);

                    if (!IsCurrentLaunch(launchId, generation))
                    {
                        return;
                    }

                    var channel = _ipcChannel;
                    if (channel is null)
                    {
                        return;
                    }

                    var fence = channel.CreateFenceStamp();
                    var ping = new IpcMessage
                    {
                        Type = IpcMessageType.HeartbeatPing,
                        Payload = fence.Serialize(),
                    };

                    if (!channel.TrySendMessage(ping, _config.HeartbeatInterval))
                    {
                        HandleWorkerFailureFenced("Heartbeat send failed", launchId, generation);
                        return;
                    }

                    // Bounded wait for the pong with matching fence stamp.
                    using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                    readCts.CancelAfter(_config.HeartbeatTimeout);

                    var (readResult, _) = await channel.ReadFencedMessageAsync(
                        IpcMessageType.HeartbeatPong, readCts.Token).ConfigureAwait(false);
                    if (readResult != IpcReadResult.Success)
                    {
                        HandleWorkerFailureFenced($"Heartbeat liveness failed: {readResult}", launchId, generation);
                        return;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
            catch (Exception)
            {
                HandleWorkerFailureFenced("Heartbeat monitor exception", launchId, generation);
            }
            finally
            {
                cts.Dispose();
            }
        });
    }

    private void StopHeartbeatMonitor()
    {
        var cts = _heartbeatCts;
        _heartbeatCts = null;
        _heartbeatTask = null;
        cts?.Cancel();
    }

    private static string? GetCurrentProcessTokenSid()
    {
        IntPtr hProcess = Kernel32Native.GetCurrentProcess();
        if (!PipeNative.OpenProcessToken(hProcess, 0x0008, out var tokenHandle))
        {
            return null;
        }

        using (tokenHandle)
        {
            return GetTokenUserSid(tokenHandle.DangerousGetHandle());
        }
    }

    internal static string? GetTokenUserSid(IntPtr tokenHandle)
    {
        if (!PipeNative.GetTokenInformation(tokenHandle, PipeNative.TokenUser, IntPtr.Zero, 0, out int needed)
            && needed == 0)
        {
            return null;
        }

        IntPtr buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!PipeNative.GetTokenInformation(tokenHandle, PipeNative.TokenUser, buffer, needed, out _))
            {
                return null;
            }

            IntPtr pSid = Marshal.ReadIntPtr(buffer);
            if (!PipeNative.ConvertSidToStringSidW(pSid, out IntPtr pStringSid))
            {
                return null;
            }

            string sid = Marshal.PtrToStringUni(pStringSid) ?? string.Empty;
            Kernel32Native.LocalFree(pStringSid);
            return sid;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            // Mark disposed first so concurrent callbacks observe it, then tear
            // down without re-entering the public disposed-guarded methods.
            _disposed = true;
            StopLifetimeMonitor();
            StopHeartbeatMonitor();

            try
            {
                // Graceful shutdown attempt; never throws from Dispose.
                if (_ipcChannel is not null)
                {
                    var fence = _ipcChannel.CreateFenceStamp();
                    _ipcChannel.TrySendMessage(
                        new IpcMessage { Type = IpcMessageType.Shutdown, Payload = fence.Serialize() },
                        TimeSpan.FromSeconds(1));
                }
            }
            catch (Exception)
            {
                // Best-effort graceful shutdown.
            }

            try
            {
                if (_childProcessHandle is not null && !_childProcessHandle.IsInvalid)
                {
                    ProcessNative.TerminateProcess(_childProcessHandle.DangerousGetHandle(), 1);
                }
            }
            catch (Exception)
            {
                // Job Object kill-on-close is the backstop.
            }

            lock (_lock)
            {
                _workerStatus = WorkerStatus.Exited;
                _currentWorker = null;
            }

            CleanupWorkerProcess();
            _job?.Dispose();
            _job = null;
        }
    }
}
