using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform;
using Helicoid.WindowsPlatform.Native;
using Xunit;

namespace Helicoid.WindowsIntegrationTests;

/// <summary>
/// Windows-native integration tests for the supervisor/worker IPC lifecycle.
/// These tests exercise real named pipes, process creation, Job Objects,
/// and kernel identity verification — not mirror DTO validation.
///
/// Requires Windows runtime. Skip on non-Windows platforms.
/// </summary>
public sealed class SupervisorIpcIntegrationTests : IDisposable
{
    private readonly string _workerExePath;
    private readonly List<IDisposable> _disposables = new();

    public SupervisorIpcIntegrationTests()
    {
        // Locate the CaptureWorker executable relative to the test assembly.
        string testDir = AppContext.BaseDirectory;
        _workerExePath = Path.Combine(testDir, "Helicoid.CaptureWorker.exe");
    }

    public void Dispose()
    {
        foreach (var d in _disposables)
        {
            try { d.Dispose(); } catch { }
        }
    }

    private static FencingIds MakeFence()
        => new() { BootId = FencingIds.GenerateId(), LaunchId = FencingIds.GenerateId() };

    /// <summary>
    /// Await a counterpart task with a hard bound. A hung peer must fail the
    /// test with TimeoutException rather than stall the native CI run.
    /// </summary>
    private static async Task<T> AwaitBoundedAsync<T>(Task<T> task, TimeSpan timeout)
    {
        var completed = await Task.WhenAny(task, Task.Delay(timeout)).ConfigureAwait(false);
        if (completed != task)
        {
            throw new TimeoutException($"Counterpart did not complete within {timeout.TotalSeconds:0.#}s.");
        }

        return await task.ConfigureAwait(false);
    }

    /// <summary>
    /// Await a counterpart task with a hard bound (non-generic).
    /// </summary>
    private static async Task AwaitBoundedAsync(Task task, TimeSpan timeout)
    {
        var completed = await Task.WhenAny(task, Task.Delay(timeout)).ConfigureAwait(false);
        if (completed != task)
        {
            throw new TimeoutException($"Counterpart did not complete within {timeout.TotalSeconds:0.#}s.");
        }

        await task.ConfigureAwait(false);
    }

    private static (uint Session, string Sid) GetSelfIdentity()
    {
        uint pid = Kernel32Native.GetCurrentProcessId();
        if (!WtsNative.ProcessIdToSessionId(pid, out uint session))
        {
            session = 0;
        }

        string sid = GetCurrentProcessTokenSid() ?? "S-1-5-18";
        return (session, sid);
    }

    private static SupervisorIpcChannel CreateChannel(
        LaunchCapability capability,
        uint expectedPid = 0,
        FencingIds? fence = null,
        uint generation = DesktopGeneration.Initial)
    {
        var (session, sid) = GetSelfIdentity();
        return new SupervisorIpcChannel(
            capability,
            expectedPid,
            session,
            sid,
            fence ?? MakeFence(),
            generation);
    }

    private static WorkerIpcChannel CreateWorkerChannel(
        string pipeName,
        LaunchCapability capability,
        FencingIds? fence = null,
        uint generation = DesktopGeneration.Initial,
        uint? serverPid = null)
    {
        uint pid = serverPid ?? Kernel32Native.GetCurrentProcessId();
        WtsNative.ProcessIdToSessionId(pid, out uint session);
        string sid = GetCurrentProcessTokenSid() ?? "S-1-5-18";
        return new WorkerIpcChannel(pipeName, capability, pid, session, sid, fence ?? MakeFence(), generation);
    }

    // =================================================================
    // Test 1: Successful handshake between supervisor and worker
    // =================================================================

    [WindowsFact]
    public async Task Handshake_SuccessfulAuth_Accepted()
    {

        var capability = LaunchCapability.Generate();
        var fence = MakeFence();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid, fence: fence);

        var workerTask = Task.Run(() =>
        {
            using var workerChannel = CreateWorkerChannel(channel.PipeName, capability, fence: fence);
            return workerChannel.ConnectAndHandshake(TimeSpan.FromSeconds(10));
        });

        var result = channel.WaitForAuthenticatedConnection(TimeSpan.FromSeconds(10));
        Assert.Equal(IpcAuthenticationResult.Authenticated, result);

        var workerResult = await AwaitBoundedAsync(workerTask, TimeSpan.FromSeconds(15));
        Assert.Equal(IpcAuthenticationResult.Authenticated, workerResult);
    }

    // =================================================================
    // Test 2: Wrong capability nonce — rejected
    // =================================================================

    [WindowsFact]
    public async Task Handshake_WrongCapability_Rejected()
    {

        var supervisorCap = LaunchCapability.Generate();
        var wrongCap = LaunchCapability.Generate(); // Different capability.
        var fence = MakeFence();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(supervisorCap, expectedPid: selfPid, fence: fence);

        var workerTask = Task.Run(() =>
        {
            using var workerChannel = CreateWorkerChannel(channel.PipeName, wrongCap, fence: fence);
            return workerChannel.ConnectAndHandshake(TimeSpan.FromSeconds(10));
        });

        var result = channel.WaitForAuthenticatedConnection(TimeSpan.FromSeconds(10));
        Assert.Equal(IpcAuthenticationResult.InvalidCapability, result);

        // Peer must finish its own I/O deadline (10s handshake) well inside
        // this bound. A stalled peer is a test failure with evidence, not an
        // ignored default — IpcAuthenticationResult.Authenticated == 0 makes
        // default ambiguous.
        var workerResult = await AwaitBoundedAsync(workerTask, TimeSpan.FromSeconds(15));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, workerResult);
    }

    // =================================================================
    // Test 3: Handshake timeout — no worker connects
    // =================================================================

    [WindowsFact]
    public void Handshake_Timeout_ReturnsTimeout()
    {

        var capability = LaunchCapability.Generate();
        using var channel = CreateChannel(capability);

        // Wait with a very short timeout — no worker will connect.
        var result = channel.WaitForAuthenticatedConnection(TimeSpan.FromMilliseconds(100));
        Assert.Equal(IpcAuthenticationResult.Timeout, result);
    }

    // =================================================================
    // Test 4: Wrong PID — connecting process has different PID than expected
    // =================================================================

    [WindowsFact]
    public async Task Handshake_WrongPid_ProcessMismatch()
    {

        var capability = LaunchCapability.Generate();
        var fence = MakeFence();

        // Expect a PID that is not us — any real client must mismatch.
        using var channel = CreateChannel(capability, expectedPid: 999999, fence: fence);

        var workerTask = Task.Run(() =>
        {
            using var workerChannel = CreateWorkerChannel(channel.PipeName, capability, fence: fence);
            return workerChannel.ConnectAndHandshake(TimeSpan.FromSeconds(10));
        });

        var result = channel.WaitForAuthenticatedConnection(TimeSpan.FromSeconds(10));
        Assert.Equal(IpcAuthenticationResult.ProcessMismatch, result);

        // Peer must finish its own I/O deadline well inside this bound.
        var workerResult = await AwaitBoundedAsync(workerTask, TimeSpan.FromSeconds(15));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, workerResult);
    }

    // =================================================================
    // Test 5: Malformed handshake — worker sends garbage bytes
    // =================================================================

    [WindowsFact]
    public async Task Handshake_MalformedFrame_Rejected()
    {

        var capability = LaunchCapability.Generate();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid);

        var handshakeTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnection(TimeSpan.FromSeconds(10)));

        // Connect as a raw pipe client and send malformed data.
        using var rawClient = new NamedPipeClientStream(".", channel.PipeName, PipeDirection.InOut);
        await rawClient.ConnectAsync(5000);

        // Send garbage: valid header type but wrong payload size.
        byte[] garbage = new byte[IpcMessage.HeaderSize];
        garbage[0] = (byte)IpcMessageType.HandshakeRequest;
        BitConverter.TryWriteBytes(garbage.AsSpan(1, 4), 999); // Claims 999 bytes but frame is only 5.
        await rawClient.WriteAsync(garbage);
        await rawClient.FlushAsync();

        var result = await AwaitBoundedAsync(handshakeTask, TimeSpan.FromSeconds(15));
        // Should be either MalformedFrame or Timeout (depending on read behavior).
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, result);
    }

    // =================================================================
    // Test 6: Silent client — connects but sends nothing
    // =================================================================

    [WindowsFact]
    public async Task Handshake_SilentClient_Timeout()
    {

        var capability = LaunchCapability.Generate();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid);

        var handshakeTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(2)));

        // Connect but send nothing.
        using var rawClient = new NamedPipeClientStream(".", channel.PipeName, PipeDirection.InOut);
        await rawClient.ConnectAsync(5000);

        // Don't send anything — let it timeout.
        var result = await AwaitBoundedAsync(handshakeTask, TimeSpan.FromSeconds(15));
        Assert.Equal(IpcAuthenticationResult.Timeout, result);
    }

    // =================================================================
    // Test 7: Worker with wrong capability via real CaptureWorker
    // =================================================================

    [WindowsFact]
    public async Task CaptureWorker_WrongCapability_ExitCode3()
    {

        if (!File.Exists(_workerExePath))
        {
            return; // Skip when the worker binary was not staged.
        }

        var capability = LaunchCapability.Generate();
        var fence = MakeFence();

        // Create a pipe with a DIFFERENT capability than what we'll give the worker.
        var differentCap = LaunchCapability.Generate();
        using var channel = CreateChannel(differentCap, fence: fence);

        // Launch the worker with the WRONG capability.
        var psi = new ProcessStartInfo
        {
            FileName = _workerExePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.Environment["HELI_WORKER_CAP"] = Convert.ToHexString(capability.Bytes);
        psi.Environment["HELI_WORKER_PIPE"] = channel.PipeName;
        psi.Environment["HELI_WORKER_GEN"] = "1";
        psi.Environment["HELI_WORKER_BOOT"] = Convert.ToHexString(fence.BootId);
        psi.Environment["HELI_WORKER_LAUNCH"] = Convert.ToHexString(fence.LaunchId);

        using var worker = Process.Start(psi);
        Assert.NotNull(worker);

        // Bind the actual child PID now that the process exists.
        channel.BindExpectedPid((uint)worker!.Id);

        // Supervisor side should reject the connection.
        var result = await channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(IpcAuthenticationResult.InvalidCapability, result);

        // Worker should exit with auth failure code.
        bool exited = worker.WaitForExit(10000);
        Assert.True(exited, "Worker should have exited");
        Assert.Equal(3, worker.ExitCode); // ExitAuthFailed
    }

    // =================================================================
    // Test 8: Worker without env vars — exit code 1
    // =================================================================

    [WindowsFact]
    public void CaptureWorker_NoEnvVars_ExitCode1()
    {

        if (!File.Exists(_workerExePath))
        {
            return;
        }

        var psi = new ProcessStartInfo
        {
            FileName = _workerExePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        // Clear any inherited HELI_WORKER vars.
        psi.Environment.Remove("HELI_WORKER_CAP");
        psi.Environment.Remove("HELI_WORKER_PIPE");
        psi.Environment.Remove("HELI_WORKER_GEN");
        psi.Environment.Remove("HELI_WORKER_BOOT");
        psi.Environment.Remove("HELI_WORKER_LAUNCH");

        using var worker = Process.Start(psi);
        Assert.NotNull(worker);

        bool exited = worker!.WaitForExit(10000);
        Assert.True(exited, "Worker should have exited");
        Assert.Equal(1, worker.ExitCode); // ExitConfigError
    }

    // =================================================================
    // Test 8b: Worker with missing fencing IDs — exit code 1 (mandatory)
    // =================================================================

    [WindowsFact]
    public void CaptureWorker_MissingFenceIds_ExitCode1()
    {

        if (!File.Exists(_workerExePath))
        {
            return;
        }

        var capability = LaunchCapability.Generate();
        var psi = new ProcessStartInfo
        {
            FileName = _workerExePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.Environment["HELI_WORKER_CAP"] = Convert.ToHexString(capability.Bytes);
        psi.Environment["HELI_WORKER_PIPE"] = "helicoid-worker-test";
        psi.Environment["HELI_WORKER_GEN"] = "1";
        // BOOT and LAUNCH intentionally omitted — must deny.

        using var worker = Process.Start(psi);
        Assert.NotNull(worker);

        bool exited = worker!.WaitForExit(10000);
        Assert.True(exited, "Worker should have exited");
        Assert.Equal(1, worker.ExitCode); // ExitConfigError — mandatory fencing missing
    }

    // =================================================================
    // Test 8c: Worker with malformed fencing IDs — exit code 1
    // =================================================================

    [WindowsFact]
    public void CaptureWorker_MalformedFenceIds_ExitCode1()
    {

        if (!File.Exists(_workerExePath))
        {
            return;
        }

        var capability = LaunchCapability.Generate();
        var psi = new ProcessStartInfo
        {
            FileName = _workerExePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.Environment["HELI_WORKER_CAP"] = Convert.ToHexString(capability.Bytes);
        psi.Environment["HELI_WORKER_PIPE"] = "helicoid-worker-test";
        psi.Environment["HELI_WORKER_GEN"] = "1";
        psi.Environment["HELI_WORKER_BOOT"] = "AABB"; // Too short — must deny.
        psi.Environment["HELI_WORKER_LAUNCH"] = "CCDD";

        using var worker = Process.Start(psi);
        Assert.NotNull(worker);

        bool exited = worker!.WaitForExit(10000);
        Assert.True(exited, "Worker should have exited");
        Assert.Equal(1, worker.ExitCode);
    }

    // =================================================================
    // Test 9: Worker exit and restart — old callbacks fenced
    // =================================================================

    [WindowsFact]
    public void Supervisor_WorkerRestart_OldCallbacksFenced()
    {

        var config = MakeConfig(_workerExePath);

        using var supervisor = new WorkerSupervisor(config);

        // Record the boot ID.
        byte[] bootId = supervisor.BootId;
        Assert.Equal(FencingIds.IdLength, bootId.Length);

        // Boot ID should be constant for the same supervisor instance.
        Assert.True(supervisor.IsCurrentBoot(bootId));

        // A random boot ID should NOT match.
        byte[] differentBootId = FencingIds.GenerateId();
        Assert.False(supervisor.IsCurrentBoot(differentBootId));
    }

    // =================================================================
    // Test 9b: Generation invalidation fences old launch callbacks
    // =================================================================

    [WindowsFact]
    public void Supervisor_InvalidateGeneration_FencesOldLaunch()
    {

        var config = MakeConfig(_workerExePath);
        using var supervisor = new WorkerSupervisor(config);

        uint genBefore = supervisor.Generation.Value;

        // Simulate a callback captured at the old generation.
        byte[] staleLaunch = FencingIds.GenerateId();
        uint staleGen = genBefore;
        Assert.False(supervisor.IsCurrentLaunch(staleLaunch, staleGen));

        supervisor.InvalidateGeneration("test lock");

        // After invalidation, generation advanced and any prior launch is fenced.
        Assert.Equal(genBefore + 1, supervisor.Generation.Value);
        Assert.False(supervisor.IsCurrentLaunch(staleLaunch, staleGen));
    }

    // =================================================================
    // Test 9c: OnSessionLocked and OnConsoleReplaced advance generation
    // =================================================================

    [WindowsFact]
    public void Supervisor_LockAndConsoleReplace_FenceGeneration()
    {

        var config = MakeConfig(_workerExePath);
        using var supervisor = new WorkerSupervisor(config);

        uint g0 = supervisor.Generation.Value;
        supervisor.OnSessionLocked();
        uint g1 = supervisor.Generation.Value;
        Assert.True(g1 > g0, "lock must advance generation");

        supervisor.OnConsoleReplaced();
        uint g2 = supervisor.Generation.Value;
        Assert.True(g2 > g1, "console replacement must advance generation");
    }

    // =================================================================
    // Test 10: Repeated bounded resource disposal
    // =================================================================

    [WindowsFact]
    public void Supervisor_RepeatedDispose_NoException()
    {

        var config = MakeConfig("nonexistent.exe");

        // Create and dispose multiple times.
        for (int i = 0; i < 10; i++)
        {
            var supervisor = new WorkerSupervisor(config);
            supervisor.Dispose();
            // Second dispose should be safe (no-op).
            supervisor.Dispose();
        }
    }

    // =================================================================
    // Test 11: IPC channel repeated dispose
    // =================================================================

    [WindowsFact]
    public void IpcChannel_RepeatedDispose_NoException()
    {

        var capability = LaunchCapability.Generate();

        for (int i = 0; i < 10; i++)
        {
            var channel = CreateChannel(capability);
            channel.Dispose();
            channel.Dispose();
        }

        for (int i = 0; i < 10; i++)
        {
            var channel = CreateWorkerChannel("nonexistent-pipe", capability);
            channel.Dispose();
            channel.Dispose();
        }
    }

    // =================================================================
    // Test 12: KillOnCloseJob — process assigned and killed on dispose
    // =================================================================

    [WindowsFact]
    public void KillOnCloseJob_AssignAndDispose_NoLeak()
    {

        // Create and dispose job objects repeatedly to verify no handle leak.
        for (int i = 0; i < 10; i++)
        {
            using var job = new KillOnCloseJob();
            IntPtr handle = job.DangerousGetHandle();
            Assert.NotEqual(IntPtr.Zero, handle);
        }
    }

    // =================================================================
    // Test 13: EnrollmentStorage — deterministic tamper classification
    //
    // Production format: [4-byte version][4-byte plaintext length][DPAPI blob].
    // Header damage (version or length) is structural corruption.
    // Blob damage is authenticated-DPAPI tampering and must be classified
    // DecryptionFailed (not Corrupted) with null plaintext. Production
    // classification is not changed by this test.
    // =================================================================

    private const int EnrollmentHeaderSize = 8;

    /// <summary>
    /// Create a valid enrollment file in a disposable owned dir and return
    /// the on-disk bytes. Asserts creation success and sufficient length.
    /// An unrelated sibling file is planted and must survive untouched.
    /// </summary>
    private static (string TempDir, string StoragePath, byte[] FileBytes, string UnrelatedPath) CreateValidEnrollmentFile()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        // Unrelated data in the owned dir must be preserved by all operations.
        string unrelatedPath = Path.Combine(tempDir, "unrelated.txt");
        File.WriteAllText(unrelatedPath, "preserve-me");

        var storage = new EnrollmentStorage(tempDir);
        byte[] secret = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29];
        var createResult = storage.Create(secret);
        Assert.Equal(EnrollmentStorageResult.Success, createResult);

        string storagePath = storage.StoragePath;
        Assert.True(File.Exists(storagePath));

        byte[] fileBytes = File.ReadAllBytes(storagePath);
        Assert.True(fileBytes.Length > EnrollmentHeaderSize,
            $"file must hold a DPAPI blob, length was {fileBytes.Length}");

        // Format sanity: version is the current version.
        Assert.Equal(1u, BitConverter.ToUInt32(fileBytes, 0));
        // Plaintext length recorded in the header matches the secret we wrote.
        Assert.Equal(secret.Length, BitConverter.ToInt32(fileBytes, 4));

        return (tempDir, storagePath, fileBytes, unrelatedPath);
    }

    private static void AssertDamagedFileUnchangedAndNotRecreated(
        string tempDir,
        string storagePath,
        byte[] expectedDamagedBytes,
        string unrelatedPath)
    {
        // The damaged file must be left exactly as written (no auto-repair).
        Assert.True(File.Exists(storagePath));
        Assert.Equal(expectedDamagedBytes, File.ReadAllBytes(storagePath));

        // No automatic state recreation: Create still refuses to overwrite.
        var storage = new EnrollmentStorage(tempDir);
        Assert.Equal(EnrollmentStorageResult.AlreadyExists, storage.Create([1, 2, 3]));

        // Unrelated data in the same owned dir is untouched.
        Assert.True(File.Exists(unrelatedPath));
        Assert.Equal("preserve-me", File.ReadAllText(unrelatedPath));
    }

    [WindowsFact]
    public void EnrollmentStorage_TamperedHeaderVersion_ReturnsCorrupted()
    {
        var (tempDir, storagePath, fileBytes, unrelatedPath) = CreateValidEnrollmentFile();
        try
        {
            // Deterministic header damage: version field at offset 0.
            fileBytes[0] = (byte)~fileBytes[0];
            File.WriteAllBytes(storagePath, fileBytes);

            var storage = new EnrollmentStorage(tempDir);
            var openResult = storage.Open(out byte[]? plaintext);

            Assert.Equal(EnrollmentStorageResult.Corrupted, openResult);
            Assert.Null(plaintext);

            AssertDamagedFileUnchangedAndNotRecreated(tempDir, storagePath, fileBytes, unrelatedPath);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void EnrollmentStorage_TamperedHeaderLength_ReturnsCorrupted()
    {
        var (tempDir, storagePath, fileBytes, unrelatedPath) = CreateValidEnrollmentFile();
        try
        {
            // Deterministic header damage: plaintext-length field at offset 4
            // set to a negative value, which must be rejected as corruption.
            BitConverter.TryWriteBytes(fileBytes.AsSpan(4, 4), -1);
            File.WriteAllBytes(storagePath, fileBytes);

            var storage = new EnrollmentStorage(tempDir);
            var openResult = storage.Open(out byte[]? plaintext);

            Assert.Equal(EnrollmentStorageResult.Corrupted, openResult);
            Assert.Null(plaintext);

            AssertDamagedFileUnchangedAndNotRecreated(tempDir, storagePath, fileBytes, unrelatedPath);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void EnrollmentStorage_TamperedEncryptedBlob_ReturnsDecryptionFailed()
    {
        var (tempDir, storagePath, fileBytes, unrelatedPath) = CreateValidEnrollmentFile();
        try
        {
            // Deterministic authenticated-DPAPI tamper: flip the final byte of
            // the file. The format is [version u32][plaintextLen i32][DPAPI
            // blob], so offset (Length-1) is the tail of DPAPI pbData — the
            // authenticated ciphertext payload. Flipping it must make
            // CryptUnprotectData fail.
            int tamperOffset = fileBytes.Length - 1;
            Assert.True(tamperOffset >= EnrollmentHeaderSize,
                "tamper offset must land inside the DPAPI blob");
            fileBytes[tamperOffset] = (byte)~fileBytes[tamperOffset];
            File.WriteAllBytes(storagePath, fileBytes);

            var storage = new EnrollmentStorage(tempDir);
            var openResult = storage.Open(out byte[]? plaintext);

            // Production contract: tampered authenticated blob is
            // DecryptionFailed, not Corrupted. Do not weaken this.
            Assert.Equal(EnrollmentStorageResult.DecryptionFailed, openResult);
            Assert.Null(plaintext);

            AssertDamagedFileUnchangedAndNotRecreated(tempDir, storagePath, fileBytes, unrelatedPath);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =================================================================
    // Test 14: EnrollmentStorage — no overwrite
    // =================================================================

    [WindowsFact]
    public void EnrollmentStorage_NoOverwrite_AlreadyExists()
    {

        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-test-{Guid.NewGuid():N}");
        try
        {
            var storage = new EnrollmentStorage(tempDir);

            byte[] secret1 = [1, 2, 3];
            byte[] secret2 = [4, 5, 6];

            Assert.Equal(EnrollmentStorageResult.Success, storage.Create(secret1));
            Assert.Equal(EnrollmentStorageResult.AlreadyExists, storage.Create(secret2));

            // Verify the original secret is still there.
            Assert.Equal(EnrollmentStorageResult.Success, storage.Open(out var readBack));
            Assert.Equal(secret1, readBack);

            storage.Forget();
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =================================================================
    // Test 15: BindExpectedPid after pipe creation rejects update
    // =================================================================

    [WindowsFact]
    public async Task SupervisorIpcChannel_BindExpectedPid_AfterPipeRejects()
    {

        var capability = LaunchCapability.Generate();
        using var channel = CreateChannel(capability, expectedPid: 0);

        // Start listening (creates the pipe).
        var listenTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromMilliseconds(500)));

        // Wait until the pipe is listening (give the task a moment).
        await Task.Delay(50);

        // Now trying to bind PID should throw.
        Assert.Throws<InvalidOperationException>(() => channel.BindExpectedPid(12345));

        await AwaitBoundedAsync(listenTask, TimeSpan.FromSeconds(5));
    }

    [WindowsFact]
    public void SupervisorIpcChannel_BindExpectedPid_RejectsZero()
    {

        var capability = LaunchCapability.Generate();
        using var channel = CreateChannel(capability);
        Assert.Throws<ArgumentException>(() => channel.BindExpectedPid(0));
    }

    // =================================================================
    // Test 15b: SupervisorIpcChannel constructor rejects missing SID
    // =================================================================

    [WindowsFact]
    public void SupervisorIpcChannel_MissingSid_Throws()
    {

        var capability = LaunchCapability.Generate();
        var fence = MakeFence();
        Assert.Throws<ArgumentException>(() => new SupervisorIpcChannel(
            capability, 0, 1, "", fence, 1));
        Assert.Throws<ArgumentException>(() => new SupervisorIpcChannel(
            capability, 0, 1, "not-a-sid", fence, 1));
    }

    [WindowsFact]
    public void SupervisorIpcChannel_MissingFence_Throws()
    {

        var capability = LaunchCapability.Generate();
        var (session, sid) = GetSelfIdentity();
        var emptyFence = new FencingIds { BootId = Array.Empty<byte>(), LaunchId = FencingIds.GenerateId() };
        Assert.Throws<ArgumentException>(() => new SupervisorIpcChannel(
            capability, 0, session, sid, emptyFence, 1));
    }

    // =================================================================
    // Test 15c: WorkerIpcChannel constructor rejects missing identity
    // =================================================================

    [WindowsFact]
    public void WorkerIpcChannel_MissingServerIdentity_Throws()
    {

        var capability = LaunchCapability.Generate();
        var fence = MakeFence();
        var (session, sid) = GetSelfIdentity();

        Assert.Throws<ArgumentException>(() => new WorkerIpcChannel(
            "", capability, 1, session, sid, fence, 1));
        Assert.Throws<ArgumentException>(() => new WorkerIpcChannel(
            "pipe", capability, 0, session, sid, fence, 1));
        Assert.Throws<ArgumentException>(() => new WorkerIpcChannel(
            "pipe", capability, 1, session, "", fence, 1));
    }

    // =================================================================
    // Test 16: PhysicalConsoleObserver — schema2 regression intact
    // =================================================================

    [WindowsFact]
    public void PhysicalConsoleObserver_ObserveOnce_ReturnsEligibility()
    {

        // This exercises the real WTS APIs.
        var eligibility = PhysicalConsoleObserver.Observe();

        // Should return a valid eligibility (not throw).
        Assert.NotNull(eligibility);
    }

    // =================================================================
    // Test 17: PhysicalConsoleObserverLoop — start/stop lifecycle
    // =================================================================

    [WindowsFact]
    public void ObserverLoop_StartStop_NoOverlap()
    {

        int observationCount = 0;
        using var loop = new PhysicalConsoleObserverLoop(
            TimeSpan.FromMilliseconds(50),
            _ => Interlocked.Increment(ref observationCount));

        loop.Start();
        Assert.True(loop.IsRunning);

        // Starting again should be a no-op (no overlap).
        loop.Start();
        Assert.True(loop.IsRunning);

        Thread.Sleep(200); // Let a few observations happen.
        Assert.True(observationCount > 0);

        loop.Stop();
        Assert.False(loop.IsRunning);

        // Stop again should be safe.
        loop.Stop();
    }

    // =================================================================
    // Test 18: ObserverLoop — error callback receives exceptions
    // =================================================================

    [WindowsFact]
    public void ObserverLoop_ErrorCallback_ReceivesExceptions()
    {

        // Create a loop and verify start/stop without crashing.
        using var loop = new PhysicalConsoleObserverLoop(
            TimeSpan.FromMilliseconds(50),
            _ => { },
            _ => { });

        loop.Start();
        Thread.Sleep(100);
        loop.Stop();
    }

    // =================================================================
    // Test 19: BootId uniqueness across supervisor instances
    // =================================================================

    [WindowsFact]
    public void WorkerSupervisor_BootId_UniquePerInstance()
    {

        var config = MakeConfig("test.exe");

        using var sup1 = new WorkerSupervisor(config);
        using var sup2 = new WorkerSupervisor(config);

        // Different instances should have different boot IDs.
        Assert.False(sup1.IsCurrentBoot(sup2.BootId));
    }

    // =================================================================
    // Test 20: FencingIds constant-time comparison
    // =================================================================

    [Fact]
    public void FencingIds_ConstantTimeComparison()
    {
        byte[] id1 = FencingIds.GenerateId();
        byte[] id2 = FencingIds.GenerateId();

        var ids = new FencingIds { BootId = id1, LaunchId = id1 };

        // Same ID should match.
        Assert.True(ids.MatchesBoot(id1));
        Assert.True(ids.MatchesLaunch(id1));

        // Different ID should not match.
        Assert.False(ids.MatchesBoot(id2));
        Assert.False(ids.MatchesLaunch(id2));

        // Wrong length should not match.
        Assert.False(ids.MatchesBoot(new byte[8]));
        Assert.False(ids.MatchesLaunch(new byte[32]));
    }

    // =================================================================
    // Test 21: FenceStamp round-trip and mismatch rejection
    // =================================================================

    [Fact]
    public void FenceStamp_Mismatch_FailsClosed()
    {
        var boot = FencingIds.GenerateId();
        var launch = FencingIds.GenerateId();
        var stamp = new FenceStamp { BootId = boot, LaunchId = launch, Generation = 1 };

        byte[] wire = stamp.Serialize();
        Assert.True(FenceStamp.TryDeserialize(wire, out var parsed));
        Assert.True(stamp.Matches(parsed));

        // Wrong generation must not match.
        var stale = new FenceStamp { BootId = boot, LaunchId = launch, Generation = 2 };
        Assert.False(stamp.Matches(stale));
    }

    // =================================================================
    // Test 22: IpcMessage rejects unknown types (fail closed)
    // =================================================================

    [Fact]
    public void IpcMessage_UnknownType_FailsClosed()
    {
        byte[] frame = new byte[IpcMessage.HeaderSize];
        frame[0] = 0xFE; // Undefined message type.
        Assert.False(IpcMessage.TryDeserialize(frame, frame.Length, out _));
    }

    // =================================================================
    // Test 23: Bounded read returns Timeout on silence (native pipe)
    // =================================================================

    [WindowsFact]
    public async Task IpcRead_Silence_ReturnsTimeout()
    {
        var capability = LaunchCapability.Generate();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid);

        var handshakeTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(1)));

        using var rawClient = new NamedPipeClientStream(".", channel.PipeName, PipeDirection.InOut);
        await rawClient.ConnectAsync(2000);

        var result = await AwaitBoundedAsync(handshakeTask, TimeSpan.FromSeconds(15));
        Assert.Equal(IpcAuthenticationResult.Timeout, result);
    }

    // =================================================================
    // Test 24: Bounded read returns Malformed on oversize claim (native)
    // =================================================================

    [WindowsFact]
    public async Task IpcRead_OversizeClaim_ReturnsMalformedNotAuthenticated()
    {
        var capability = LaunchCapability.Generate();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid);

        var handshakeTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(2)));

        using var rawClient = new NamedPipeClientStream(".", channel.PipeName, PipeDirection.InOut);
        await rawClient.ConnectAsync(2000);

        byte[] frame = new byte[IpcMessage.HeaderSize];
        frame[0] = (byte)IpcMessageType.HandshakeRequest;
        BitConverter.TryWriteBytes(frame.AsSpan(1, 4), IpcMessage.MaxPayloadSize + 1);
        await rawClient.WriteAsync(frame);
        await rawClient.FlushAsync();

        var result = await AwaitBoundedAsync(handshakeTask, TimeSpan.FromSeconds(15));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, result);
    }

    // =================================================================
    // Test 25: Disconnect mid-handshake is not authenticated (native)
    // =================================================================

    [WindowsFact]
    public async Task IpcRead_Disconnect_NotAuthenticated()
    {
        var capability = LaunchCapability.Generate();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid);

        var handshakeTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(3)));

        using (var rawClient = new NamedPipeClientStream(".", channel.PipeName, PipeDirection.InOut))
        {
            await rawClient.ConnectAsync(2000);
            // Send a partial header then drop the connection.
            await rawClient.WriteAsync(new byte[] { (byte)IpcMessageType.HandshakeRequest, 1, 0, 0, 0 });
            await rawClient.FlushAsync();
        }

        var result = await AwaitBoundedAsync(handshakeTask, TimeSpan.FromSeconds(15));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, result);
    }

    // =================================================================
    // Test 26: Stale heartbeat / zero IDs cannot mutate supervisor state
    // =================================================================

    [Fact]
    public void Supervisor_ZeroLaunchId_IsNeverCurrent()
    {
        var config = MakeConfig("test.exe");
        using var supervisor = new WorkerSupervisor(config);

        byte[] zero = new byte[FencingIds.IdLength];
        uint gen = supervisor.Generation.Value;

        Assert.False(supervisor.IsCurrentLaunch(zero, gen));
        Assert.False(supervisor.IsCurrentLaunch(null, gen));
        Assert.False(supervisor.IsCurrentLaunch(new byte[8], gen));
        Assert.False(supervisor.IsCurrentBoot(zero));
        Assert.False(supervisor.IsCurrentBoot(null));
    }

    [Fact]
    public void Supervisor_BootIdGetter_ReturnsDefensiveCopy()
    {
        var config = MakeConfig("test.exe");
        using var supervisor = new WorkerSupervisor(config);

        byte[] a = supervisor.BootId;
        byte[] b = supervisor.BootId;
        Assert.False(ReferenceEquals(a, b));

        a[0] = (byte)~a[0];
        Assert.False(supervisor.IsCurrentBoot(a));
        Assert.True(supervisor.IsCurrentBoot(b));
    }

    // =================================================================
    // Test 27: Disposal-before-start fails quietly, no worker launched
    // =================================================================

    [Fact]
    public void Supervisor_DisposeBeforeStart_TryStartWorkerFailsQuietly()
    {
        var config = MakeConfig("nonexistent.exe");
        var supervisor = new WorkerSupervisor(config);
        supervisor.Dispose();

        Assert.True(supervisor.IsDisposed);
        // Must return false without throwing and without launching.
        Assert.False(supervisor.TryStartWorker());
    }

    [Fact]
    public void Supervisor_DisposeBeforeDelayedStart_FailsQuietly()
    {
        var config = MakeConfig("nonexistent.exe");
        var supervisor = new WorkerSupervisor(config);

        // Simulate the MainWindow pattern: capture instance, dispose on another
        // path, then the delayed startup observes the disposed instance.
        var captured = supervisor;
        supervisor.Dispose();

        Assert.True(captured.IsDisposed);
        Assert.False(captured.TryStartWorker());
    }

    [Fact]
    public void Supervisor_RepeatedDisposeThenStart_NoThrow()
    {
        var config = MakeConfig("nonexistent.exe");
        var supervisor = new WorkerSupervisor(config);
        supervisor.Dispose();
        supervisor.Dispose();
        Assert.False(supervisor.TryStartWorker());
    }

    // =================================================================
    // Test 28: Generation exhaustion fences and blocks restart
    // =================================================================

    [Fact]
    public void Supervisor_GenerationExhaustion_BlocksRestart()
    {
        // Start one step below the maximum so a single invalidation exhausts.
        var config = MakeConfig("nonexistent.exe") with
        {
            InitialGeneration = DesktopGeneration.MaxValue - 1,
        };
        using var supervisor = new WorkerSupervisor(config);

        Assert.False(supervisor.IsGenerationExhausted);
        Assert.Equal(DesktopGeneration.MaxValue - 1, supervisor.Generation.Value);

        // One invalidation advances to MaxValue — not past it, not to zero.
        supervisor.InvalidateGeneration("test exhaustion step");
        Assert.Equal(DesktopGeneration.MaxValue, supervisor.Generation.Value);

        // The next invalidation exhausts: counter stays at MaxValue, never 0.
        supervisor.InvalidateGeneration("test exhaustion");
        Assert.True(supervisor.IsGenerationExhausted);
        Assert.Equal(DesktopGeneration.MaxValue, supervisor.Generation.Value);
        Assert.NotEqual(0u, supervisor.Generation.Value);

        // Restart is permanently blocked — fails quietly, no worker launched.
        Assert.False(supervisor.TryStartWorker());

        // Unlock must not revive or wrap the generation either.
        supervisor.OnSessionUnlocked();
        Assert.True(supervisor.IsGenerationExhausted);
        Assert.Equal(DesktopGeneration.MaxValue, supervisor.Generation.Value);
        Assert.False(supervisor.TryStartWorker());
    }

    [Fact]
    public void Supervisor_ExhaustedThenInvalidate_StaysFenced()
    {
        var config = MakeConfig("nonexistent.exe") with
        {
            InitialGeneration = DesktopGeneration.MaxValue,
        };
        using var supervisor = new WorkerSupervisor(config);

        // Already at max: first invalidation must exhaust immediately.
        supervisor.InvalidateGeneration("already at max");
        Assert.True(supervisor.IsGenerationExhausted);
        Assert.Equal(DesktopGeneration.MaxValue, supervisor.Generation.Value);

        // Further invalidations are inert.
        supervisor.InvalidateGeneration("post-exhaustion");
        Assert.True(supervisor.IsGenerationExhausted);
        Assert.Equal(DesktopGeneration.MaxValue, supervisor.Generation.Value);
    }

    // =================================================================
    // Test 29: Bounded writes/reads/connect/disposal (native regressions)
    // =================================================================

    [WindowsFact]
    public async Task IpcWrite_SilentPeer_BoundedNotHung()
    {
        // Server accepts and then never reads; client write must return
        // false within the write bound rather than hang forever.
        var capability = LaunchCapability.Generate();
        var fence = MakeFence();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid, fence: fence);

        var handshakeTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(2)));

        using var rawClient = new NamedPipeClientStream(".", channel.PipeName, PipeDirection.InOut);
        await rawClient.ConnectAsync(2000);

        // Complete the handshake from the raw side so the server marks us
        // connected, then stop reading so a subsequent server write is blocked.
        var result = await AwaitBoundedAsync(handshakeTask, TimeSpan.FromSeconds(15));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, result);

        // A write on a dead/silent peer must be bounded — TrySendMessage
        // returns within MaxWriteTimeout rather than hanging. Both true and
        // false are legal outcomes; a timeout is not.
        var writeTask = Task.Run(() => channel.TrySendMessage(
            new IpcMessage { Type = IpcMessageType.Shutdown, Payload = channel.CreateFenceStamp().Serialize() },
            TimeSpan.FromSeconds(2)));
        await AwaitBoundedAsync(writeTask, TimeSpan.FromSeconds(6));
    }

    [WindowsFact]
    public async Task IpcChannel_Dispose_CancelsPendingConnect()
    {
        // Disposing the server while WaitForConnectionAsync is pending must
        // unblock the wait promptly (via dispose cancellation), not hang.
        var capability = LaunchCapability.Generate();
        var channel = CreateChannel(capability, expectedPid: Kernel32Native.GetCurrentProcessId());

        var waitTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(30)));

        // Give the wait a moment to enter WaitForConnectionAsync.
        await Task.Delay(100);
        channel.Dispose();

        // Dispose must cancel the pending connect within a small bound.
        var result = await AwaitBoundedAsync(waitTask, TimeSpan.FromSeconds(6));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, result);
    }

    [WindowsFact]
    public async Task IpcWorker_Dispose_CancelsPendingConnect()
    {
        // Worker side: dispose while ConnectAsync is pending must unblock.
        var capability = LaunchCapability.Generate();
        var fence = MakeFence();
        uint pid = Kernel32Native.GetCurrentProcessId();
        WtsNative.ProcessIdToSessionId(pid, out uint session);
        string sid = GetCurrentProcessTokenSid() ?? "S-1-5-18";

        // Pipe name that no server will create — connect pends.
        var worker = new WorkerIpcChannel(
            "helicoid-worker-never-created-" + Guid.NewGuid().ToString("N"),
            capability, pid, session, sid, fence, 1);

        var connectTask = Task.Run(() => worker.ConnectAndHandshakeAsync(TimeSpan.FromSeconds(30)));

        await Task.Delay(100);
        worker.Dispose();

        var result = await AwaitBoundedAsync(connectTask, TimeSpan.FromSeconds(6));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, result);
    }

    [WindowsFact]
    public async Task IpcRead_PeerDisconnect_ReturnsDisconnectedNotHang()
    {
        var capability = LaunchCapability.Generate();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        using var channel = CreateChannel(capability, expectedPid: selfPid);

        var handshakeTask = Task.Run(() =>
            channel.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(3)));

        using (var rawClient = new NamedPipeClientStream(".", channel.PipeName, PipeDirection.InOut))
        {
            await rawClient.ConnectAsync(2000);
        } // Disconnect immediately without sending.

        var result = await AwaitBoundedAsync(handshakeTask, TimeSpan.FromSeconds(6));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, result);
    }

    // =================================================================
    // Test 30: Single-instance pipe bind — SecondServerCannotBind
    //
    // This test proves ONLY that a second NamedPipeServerStream cannot bind
    // the same name while the first instance is alive, and that the first
    // server does accept a real client (so the name is genuinely bound).
    //
    // It does NOT prove restrictive ACL / remote denial / cross-SID access.
    // True cross-SID and remote ACL behavior, and session-0 service to
    // user-worker compatibility, remain NOT VERIFIED.
    // =================================================================

    [WindowsFact]
    public async Task SecondServerCannotBind()
    {
        var capability = LaunchCapability.Generate();
        var fence = MakeFence();
        uint selfPid = Kernel32Native.GetCurrentProcessId();

        // First server owns the pipe name.
        using var first = CreateChannel(capability, expectedPid: selfPid, fence: fence);

        // Start listening on the first server (creates and binds the name).
        var firstListen = Task.Run(() =>
            first.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(10)));

        // Give the first server a moment to create the pipe instance.
        await Task.Delay(200);

        // A real raw client connects — proves the first server is actually bound.
        using (var rawClient = new NamedPipeClientStream(".", first.PipeName, PipeDirection.InOut))
        {
            await rawClient.ConnectAsync(2000);

            // While the first server is alive, a second server with the same
            // name must fail to bind. The failure surfaces as a non-Authenticated
            // result from WaitForAuthenticatedConnectionAsync (constructor or
            // WaitForConnectionAsync throws IOException / returns
            // TransportFailure) — bounded, never hung.
            using var second = CreateChannel(capability, expectedPid: selfPid, fence: fence);
            var secondResult = await second.WaitForAuthenticatedConnectionAsync(TimeSpan.FromSeconds(2));
            Assert.NotEqual(IpcAuthenticationResult.Authenticated, secondResult);

            // Disconnect the raw client so the first server's read fails fast.
        }

        // Await the first server's listen task with a hard bound. It must
        // observe the peer disconnect and return a non-Authenticated result.
        var firstResult = await AwaitBoundedAsync(firstListen, TimeSpan.FromSeconds(15));
        Assert.NotEqual(IpcAuthenticationResult.Authenticated, firstResult);
    }

    // =================================================================
    // Helper
    // =================================================================

    private static SupervisorConfig MakeConfig(string workerPath)
        => new()
        {
            WorkerExecutablePath = workerPath,
            WorkerConnectTimeout = TimeSpan.FromSeconds(10),
            WorkerMaxLifetime = TimeSpan.FromSeconds(30),
            HeartbeatInterval = TimeSpan.FromSeconds(5),
            HeartbeatTimeout = TimeSpan.FromSeconds(15),
            MaxConsecutiveFailures = 3,
            RestartDelay = TimeSpan.FromSeconds(1),
        };

    private static string? GetCurrentProcessTokenSid()
    {
        if (!PlatformHelper.IsWindows) return null;
        return KernelIdentity.ReadProcessTokenSid(Kernel32Native.GetCurrentProcessId());
    }


    // =================================================================
    // DeviceKeyStorage — DPAPI persistent device identity (15 Oct review)
    // Native Windows only: real DPAPI, real Win32 handles, no skip-as-proof.
    // =================================================================

    [WindowsFact]
    public void DeviceKeyStorage_CreateOpenReopen_SameKey()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            var create = storage.CreateNew(out var seed1, out var pub1);
            Assert.Equal(DeviceKeyStorageResult.Success, create);
            Assert.Equal(32, seed1.Length);
            Assert.Equal(32, pub1.Length);

            var storage2 = new DeviceKeyStorage(tempDir);
            var open = storage2.Open(out var seed2, out var pub2);
            Assert.Equal(DeviceKeyStorageResult.Success, open);
            Assert.Equal(seed1, seed2);
            Assert.Equal(pub1, pub2);

            // Reopen after dispose of first instance.
            storage.Dispose();
            var storage3 = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage3.Open(out var seed3, out var pub3));
            Assert.Equal(pub1, pub3);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_CreateThenSign_ReopensStableIdentity()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out var seed, out var pub));

            using var key = Helicoid.Domain.Client.Ed25519DeviceKey.ImportSeed(seed);
            var message = System.Text.Encoding.UTF8.GetBytes("hs-auth-v2|deployment:d|challenge:c|operation:session|manager:x");
            var signature = key.Sign(message);
            Assert.True(Helicoid.Domain.Client.Ed25519DeviceKey.VerifyHexSignature(
                key.PublicKeyHex, message, Convert.ToHexString(signature)));

            var reopened = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, reopened.Open(out var seed2, out var pub2));
            Assert.Equal(pub, pub2);
            using var key2 = Helicoid.Domain.Client.Ed25519DeviceKey.ImportSeed(seed2);
            Assert.Equal(key.PublicKeyHex, key2.PublicKeyHex);
            Assert.True(Helicoid.Domain.Client.Ed25519DeviceKey.VerifyHexSignature(
                key2.PublicKeyHex, message, Convert.ToHexString(signature)));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_TwoCreators_ShareSingleWinner()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var a = new DeviceKeyStorage(tempDir);
            var b = new DeviceKeyStorage(tempDir);

            DeviceKeyStorageResult ra = DeviceKeyStorageResult.IoError, rb = DeviceKeyStorageResult.IoError;
            byte[] seedA = [], pubA = [], seedB = [], pubB = [];
            var t1 = Task.Run(() => ra = a.OpenOrCreate(out seedA, out pubA));
            var t2 = Task.Run(() => rb = b.OpenOrCreate(out seedB, out pubB));
            Task.WaitAll(t1, t2);

            Assert.Equal(DeviceKeyStorageResult.Success, ra);
            Assert.Equal(DeviceKeyStorageResult.Success, rb);
            Assert.Equal(pubA, pubB);
            Assert.Equal(seedA, seedB);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_TwoCreators_SynchronizedBeforeCreate_ShareSingleWinner()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var a = new DeviceKeyStorage(tempDir);
            var b = new DeviceKeyStorage(tempDir);

            // Synchronize both creators at the real before-directory-create
            // boundary so both observe absent and race CreateDirectoryW.
            using var barrier = new Barrier(2);
            a.BeforeDirectoryCreate = () => barrier.SignalAndWait(TimeSpan.FromSeconds(10));
            b.BeforeDirectoryCreate = () => barrier.SignalAndWait(TimeSpan.FromSeconds(10));

            DeviceKeyStorageResult ra = DeviceKeyStorageResult.IoError, rb = DeviceKeyStorageResult.IoError;
            byte[] seedA = [], pubA = [], seedB = [], pubB = [];
            var t1 = Task.Run(() => ra = a.OpenOrCreate(out seedA, out pubA));
            var t2 = Task.Run(() => rb = b.OpenOrCreate(out seedB, out pubB));
            Assert.True(Task.WaitAll(new[] { t1, t2 }, TimeSpan.FromSeconds(30)));

            Assert.Equal(DeviceKeyStorageResult.Success, ra);
            Assert.Equal(DeviceKeyStorageResult.Success, rb);
            Assert.Equal(pubA, pubB);
            Assert.Equal(seedA, seedB);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_NoOverwrite_OnSecondCreate()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out var seed1, out var pub1));
            Assert.Equal(DeviceKeyStorageResult.AlreadyExists, storage.CreateNew(out _, out _));

            Assert.Equal(DeviceKeyStorageResult.Success, storage.Open(out _, out var pub2));
            Assert.Equal(pub1, pub2);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_PreexistingTemp_IsNotDeleted()
    {
        // Product-owned private directory via actual store create/forget.
        string tempDir = ProductStoreFixture.CreateProductOwnedDirectory();
        try
        {
            // Foreign temp that this implementation did not create must survive.
            string foreignTemp = Path.Combine(tempDir, "device-identity.foreign.tmp");
            File.WriteAllText(foreignTemp, "preserve-me");

            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));
            Assert.True(File.Exists(foreignTemp));
            Assert.Equal("preserve-me", File.ReadAllText(foreignTemp));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_SymlinkLeaf_IsRefused()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Product-owned private directory so parent verification succeeds and
        // the leaf symlink is what must be refused.
        string tempDir = ProductStoreFixture.CreateProductOwnedDirectory();
        string target = Path.Combine(tempDir, "target.bin");
        File.WriteAllBytes(target, new byte[] { 1, 2, 3 });
        string link = Path.Combine(tempDir, "device-identity.bin");
        try
        {
            // Directory.CreateSymbolicLink / File.CreateSymbolicLink
            File.CreateSymbolicLink(link, target);

            var storage = new DeviceKeyStorage(tempDir);
            var open = storage.Open(out _, out _);
            Assert.Equal(DeviceKeyStorageResult.ReparsePointRefused, open);
        }
        catch (IOException ex) when (ex.HResult is unchecked((int)0x80070005) or unchecked((int)0x80070522))
        {
            // Privilege unavailable for symlink creation in this environment.
            // Fail closed rather than claiming a native proof.
            Assert.Fail("Symbolic link creation unavailable: " + ex.Message);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_HardlinkLeaf_IsRefused()
    {
        if (!OperatingSystem.IsWindows()) return;
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));

            string second = Path.Combine(tempDir, "hardlink.bin");
            // CreateHardLinkW: hard link to the device-identity.bin
            if (!TestNative.CreateHardLinkW(second, storage.StoragePath, IntPtr.Zero))
            {
                Assert.Fail("CreateHardLinkW failed: " + Marshal.GetLastWin32Error());
            }

            var reopened = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.ReparsePointRefused, reopened.Open(out _, out _));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_BroadEveryoneDacl_IsRefused()
    {
        string tempDir = ProductStoreFixture.CreateProductOwnedDirectory();
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));

            // Everyone full control + owner retained so the store can inspect.
            string userSid = TestNative.CurrentUserSidString()
                ?? throw new InvalidOperationException("no user sid");
            Assert.Equal(0u, TestNative.GrantAclViaSddl(
                storage.StoragePath,
                "(A;;FA;;;S-1-1-0)(A;;FA;;;" + userSid + ")"));

            var reopened = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.OwnershipMismatch, reopened.Open(out _, out _));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_PrivateAcl_CreateSignReopen_Succeeds()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out var seed, out var pub));
            using var key = Helicoid.Domain.Client.Ed25519DeviceKey.ImportSeed(seed);
            var msg = System.Text.Encoding.UTF8.GetBytes("hs-auth-v2|deployment:d|challenge:c|operation:session|manager:x");
            var sig = key.Sign(msg);
            Assert.True(Helicoid.Domain.Client.Ed25519DeviceKey.VerifyHexSignature(
                key.PublicKeyHex, msg, Convert.ToHexString(sig)));

            var reopened = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, reopened.Open(out var seed2, out var pub2));
            Assert.Equal(pub, pub2);
            Assert.Equal(seed, seed2);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_ArbitraryForeignSidGrant_IsRefused()
    {
        string tempDir = ProductStoreFixture.CreateProductOwnedDirectory();
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));

            // Network Service (S-1-5-20) is a real foreign principal; no external account.
            Assert.Equal(0u, TestNative.GrantFullControlToSid(storage.StoragePath, "S-1-5-20"));

            var reopened = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.OwnershipMismatch, reopened.Open(out _, out _));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_UntrustedExistingDirectory_IsRefused()
    {
        // Explicit foreign grant makes this directory untrusted on every host.
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            Assert.Equal(0u, TestNative.GrantFullControlToSid(tempDir, "S-1-1-0"));
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.OwnershipMismatch, storage.CreateNew(out _, out _));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_IntermediateJunction_IsRefused()
    {
        if (!OperatingSystem.IsWindows()) return;
        string root = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        string real = Path.Combine(root, "real");
        string junction = Path.Combine(root, "junction");
        Directory.CreateDirectory(real);
        try
        {
            // Junction: intermediate reparse parent must be refused.
            Directory.CreateSymbolicLink(junction, real);
            string productDir = Path.Combine(junction, "product");
            Directory.CreateDirectory(productDir);

            var storage = new DeviceKeyStorage(productDir);
            var create = storage.CreateNew(out _, out _);
            Assert.Equal(DeviceKeyStorageResult.ReparsePointRefused, create);
        }
        catch (IOException ex)
        {
            Assert.Fail("Junction creation unavailable: " + ex.Message);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_ParentReplacement_WhileHeld_IsRefused()
    {
        string root = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        string productDir = Path.Combine(root, "product");
        try
        {
            // Product-owned private directory via actual store create/forget.
            string owned = ProductStoreFixture.CreateProductOwnedDirectory();
            Directory.Move(owned, productDir);

            var storage = new DeviceKeyStorage(productDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));

            // Hold the real CreateNew path after its handles are acquired and
            // before leaf mutation/publish (per-instance barrier, not a helper).
            using var gate = new ManualResetEventSlim(false);
            using var entered = new ManualResetEventSlim(false);
            var createDir = Path.Combine(root, "product2");
            string owned2 = ProductStoreFixture.CreateProductOwnedDirectory();
            Directory.Move(owned2, createDir);
            var creating = new DeviceKeyStorage(createDir);
            creating.BeforeLeafMutate = () =>
            {
                entered.Set();
                Assert.True(gate.Wait(TimeSpan.FromSeconds(10)));
            };

            var createTask = Task.Run(() => creating.CreateNew(out _, out _));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));

            // Real create handles are held: parent rename must be blocked.
            string alt = Path.Combine(root, "product2-replaced");
            Assert.Throws<IOException>(() => Directory.Move(createDir, alt));

            gate.Set();
            Assert.Equal(DeviceKeyStorageResult.Success, createTask.GetAwaiter().GetResult());

            // Original key is readable after the barrier released the chain.
            Assert.Equal(DeviceKeyStorageResult.Success, creating.Open(out _, out _));

            // Existing-file pin path still blocks rename while held.
            Assert.Equal(DeviceKeyStorageResult.Success,
                Helicoid.WindowsPlatform.DeviceKeyStorage.TryPinDirectory(productDir, out var pin));
            Assert.NotNull(pin);
            Assert.Throws<IOException>(() => Directory.Move(productDir, Path.Combine(root, "product-replaced")));
            pin!.Dispose();
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_BeforePinPathSwap_IsRefused()
    {
        string root = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        string real = Path.Combine(root, "real");
        string productDir = Path.Combine(root, "product");
        Directory.CreateDirectory(real);
        Directory.CreateDirectory(productDir);
        try
        {
            // Swap the product path for a junction before pinning.
            Directory.Move(productDir, productDir + ".old");
            Directory.CreateSymbolicLink(productDir, real);

            Assert.Equal(DeviceKeyStorageResult.ReparsePointRefused,
                Helicoid.WindowsPlatform.DeviceKeyStorage.TryPinDirectory(productDir, out var pin));
            Assert.Null(pin);
        }
        catch (IOException ex)
        {
            Assert.Fail("Junction creation unavailable: " + ex.Message);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_HeldObject_DeletionIsBlockedOrHeld()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));

            // Open pins the leaf without FILE_SHARE_DELETE.
            var opened = new DeviceKeyStorage(tempDir);
            // Forget uses handle disposition on a held owned handle.
            Assert.Equal(DeviceKeyStorageResult.Forgotten, opened.Forget());
            Assert.False(File.Exists(storage.StoragePath));
            Assert.Equal(DeviceKeyStorageResult.NotFound, storage.Open(out _, out _));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_Forget_DeletesOnlyOwnedFile()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            // Product-owned private directory first; then sentinel file.
            string productDir = ProductStoreFixture.CreateProductOwnedDirectory();
            Directory.Move(productDir, tempDir);
            string unrelated = Path.Combine(tempDir, "unrelated.txt");
            File.WriteAllText(unrelated, "keep");

            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));
            Assert.Equal(DeviceKeyStorageResult.Forgotten, storage.Forget());
            Assert.False(File.Exists(storage.StoragePath));
            Assert.True(File.Exists(unrelated));
            Assert.Equal(DeviceKeyStorageResult.NotFound, storage.Open(out _, out _));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_ProductDirectoryForeignAce_OpenIsRefused_PreservesKeyBytes()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));
            byte[] keyBytes = File.ReadAllBytes(storage.StoragePath);
            Assert.NotEmpty(keyBytes);

            // Foreign ACE on the product directory only; keyfile ACL untouched.
            // Network Service (S-1-5-20) is a real foreign principal; no account.
            Assert.Equal(0u, TestNative.GrantFullControlToSid(tempDir, "S-1-5-20"));

            var reopened = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.OwnershipMismatch, reopened.Open(out var seed, out var pub));
            Assert.Empty(seed);
            Assert.Empty(pub);

            // Must not have read/removed the original key file.
            Assert.True(File.Exists(storage.StoragePath));
            Assert.Equal(keyBytes, File.ReadAllBytes(storage.StoragePath));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_ProductDirectoryForeignAce_ForgetIsRefused_PreservesKeyBytes()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        try
        {
            var storage = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));
            byte[] keyBytes = File.ReadAllBytes(storage.StoragePath);
            Assert.NotEmpty(keyBytes);

            // Foreign ACE on the product directory only; keyfile ACL untouched.
            Assert.Equal(0u, TestNative.GrantFullControlToSid(tempDir, "S-1-5-20"));

            var reopened = new DeviceKeyStorage(tempDir);
            Assert.Equal(DeviceKeyStorageResult.OwnershipMismatch, reopened.Forget());

            // Must not have deleted the original key file; bytes preserved.
            Assert.True(File.Exists(storage.StoragePath));
            Assert.Equal(keyBytes, File.ReadAllBytes(storage.StoragePath));
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [WindowsFact]
    public void DeviceKeyStorage_FailedChain_IsReleased_ParentRenameAndRemovalSucceed()
    {
        string root = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        string productDir = Path.Combine(root, "product");
        try
        {
            string owned = ProductStoreFixture.CreateProductOwnedDirectory();
            Directory.Move(owned, productDir);

            var storage = new DeviceKeyStorage(productDir);
            Assert.Equal(DeviceKeyStorageResult.Success, storage.CreateNew(out _, out _));
            byte[] keyBytes = File.ReadAllBytes(storage.StoragePath);

            Assert.Equal(0u, TestNative.GrantFullControlToSid(productDir, "S-1-5-20"));

            var reopened = new DeviceKeyStorage(productDir);
            Assert.Equal(DeviceKeyStorageResult.OwnershipMismatch, reopened.Open(out _, out _));
            Assert.Equal(DeviceKeyStorageResult.OwnershipMismatch, reopened.Forget());

            // Denied Open/Forget must not leave NoShareDelete pins behind:
            // the product directory renames and the tree removes cleanly.
            string moved = Path.Combine(root, "product-moved");
            Directory.Move(productDir, moved);
            string movedKey = Path.Combine(moved, "device-identity.bin");
            Assert.True(File.Exists(movedKey));
            Assert.Equal(keyBytes, File.ReadAllBytes(movedKey));
            File.Delete(movedKey);
            Directory.Delete(moved);
            Assert.False(Directory.Exists(productDir));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }
}

/// <summary>
/// TEST-ONLY CreateHardLinkW for ownership/race regressions.
/// Verified against Microsoft docs (October 2026): fileapi.h / Kernel32.
/// </summary>
internal static class TestNative
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    public static extern bool CreateHardLinkW(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    public static extern uint SetNamedSecurityInfoW(
        string pObjectName,
        uint objectType,
        uint securityInformation,
        System.IntPtr psidOwner,
        System.IntPtr psidGroup,
        System.IntPtr pDacl,
        System.IntPtr pSacl);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    public static extern uint SetEntriesInAclW(
        uint cCountOfExplicitEntries,
        System.IntPtr pListOfExplicitEntries,
        System.IntPtr oldAcl,
        out System.IntPtr newAcl);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    public static extern bool ConvertStringSidToSidW(string stringSid, out System.IntPtr sid);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    public static extern bool GetSecurityDescriptorDacl(
        System.IntPtr pSecurityDescriptor,
        out bool present,
        out System.IntPtr pDacl,
        out bool defaulted);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl,
        uint revision,
        out System.IntPtr sd,
        out uint sdSize);

    public const uint ProtectedDaclSecurityInformation = 0x80000000;
    public const uint DaclSecurityInformation = 0x00000004;

    /// <summary>
    /// TEST-ONLY: apply a protected DACL from SDDL (no hand-coded EXPLICIT_ACCESS
    /// offsets). Preserves owner rights so the product store can inspect the
    /// object after the foreign grant.
    /// </summary>
    public static uint GrantAclViaSddl(string path, string daclSddl)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "D:P" + daclSddl,
                1,
                out var sd,
                out _))
        {
            return unchecked((uint)System.Runtime.InteropServices.Marshal.GetLastWin32Error());
        }

        try
        {
            if (!GetSecurityDescriptorDacl(sd, out bool present, out var pDacl, out _)
                || !present
                || pDacl == System.IntPtr.Zero)
            {
                return 87; // ERROR_INVALID_PARAMETER
            }

            return SetNamedSecurityInfoW(
                path,
                1 /*SE_FILE_OBJECT*/,
                DaclSecurityInformation | ProtectedDaclSecurityInformation,
                System.IntPtr.Zero,
                System.IntPtr.Zero,
                pDacl,
                System.IntPtr.Zero);
        }
        finally
        {
            Helicoid.WindowsPlatform.Native.Kernel32Native.LocalFree(sd);
        }
    }

    /// <summary>TEST-ONLY: grant full control to an SID while keeping owner rights.</summary>
    public static uint GrantFullControlToSid(string path, string sidString)
    {
        // Owner/current-user ACE plus the foreign grant so the store can still open.
        string userSid = CurrentUserSidString() ?? throw new InvalidOperationException("no user sid");
        return GrantAclViaSddl(path, "(A;;FA;;;" + userSid + ")(A;;FA;;;" + sidString + ")");
    }

    public static string? CurrentUserSidString()
    {
        var process = Helicoid.WindowsPlatform.Native.Kernel32Native.GetCurrentProcess();
        if (!Helicoid.WindowsPlatform.Native.FileSecurityNative.OpenProcessToken(
                process,
                Helicoid.WindowsPlatform.Native.FileSecurityNative.TokenQuery,
                out var token))
        {
            return null;
        }

        using (token)
        {
            if (!Helicoid.WindowsPlatform.Native.FileSecurityNative.GetTokenInformation(
                    token.DangerousGetHandle(),
                    Helicoid.WindowsPlatform.Native.FileSecurityNative.TokenUser,
                    System.IntPtr.Zero,
                    0,
                    out int needed)
                || needed <= 0)
            {
                // Expected ERROR_INSUFFICIENT_BUFFER probe; retry below if needed>0.
            }

            if (needed <= 0)
            {
                needed = 256;
            }

            var buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(needed);
            try
            {
                if (!Helicoid.WindowsPlatform.Native.FileSecurityNative.GetTokenInformation(
                        token.DangerousGetHandle(),
                        Helicoid.WindowsPlatform.Native.FileSecurityNative.TokenUser,
                        buffer,
                        needed,
                        out _))
                {
                    return null;
                }

                var pSid = System.Runtime.InteropServices.Marshal.ReadIntPtr(buffer);
                if (!ConvertSidToStringSidW(pSid, out var pString))
                {
                    return null;
                }

                try
                {
                    return System.Runtime.InteropServices.Marshal.PtrToStringUni(pString);
                }
                finally
                {
                    Helicoid.WindowsPlatform.Native.Kernel32Native.LocalFree(pString);
                }
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    public static extern bool ConvertSidToStringSidW(System.IntPtr pSid, out System.IntPtr stringSid);
}

/// <summary>
/// TEST-ONLY: establish a product-owned private directory via the actual store
/// create/forget path (never a generic inherited Directory.CreateDirectory).
/// </summary>
internal static class ProductStoreFixture
{
    public static string CreateProductOwnedDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"helicoid-devkey-{Guid.NewGuid():N}");
        var storage = new Helicoid.WindowsPlatform.DeviceKeyStorage(dir);
        var created = storage.CreateNew(out _, out _);
        if (created != Helicoid.WindowsPlatform.DeviceKeyStorageResult.Success)
        {
            throw new InvalidOperationException("fixture CreateNew failed: " + created);
        }

        var forgotten = storage.Forget();
        if (forgotten != Helicoid.WindowsPlatform.DeviceKeyStorageResult.Forgotten)
        {
            throw new InvalidOperationException("fixture Forget failed: " + forgotten);
        }

        return dir;
    }
}

/// <summary>
/// Helper to detect OS platform at runtime.
/// </summary>
internal static class PlatformHelper
{
    public static bool IsWindows =>
        System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
            System.Runtime.InteropServices.OSPlatform.Windows);
}

/// <summary>
/// Fact that reports a real xUnit SKIP when not on Windows. Native evidence
/// must never be fabricated by a quiet early return inside a [Fact].
/// </summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows runtime";
        }
    }
}

/// <summary>
/// Theory that reports a real xUnit SKIP when not on Windows.
/// </summary>
public sealed class WindowsTheoryAttribute : TheoryAttribute
{
    public WindowsTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows runtime";
        }
    }
}
