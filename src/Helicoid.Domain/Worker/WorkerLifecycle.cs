namespace Helicoid.Domain.Worker;

/// <summary>
/// Worker lifecycle status. Reflects the current state of the child worker
/// process as tracked by the supervisor. Status transitions are one-directional
/// within a generation; restart creates a new generation.
/// </summary>
public enum WorkerStatus
{
    /// <summary>No worker process has been started.</summary>
    NotStarted = 0,

    /// <summary>Worker process is starting (process created, not yet connected).</summary>
    Starting = 1,

    /// <summary>Worker connected and authenticated via IPC.</summary>
    Connected = 2,

    /// <summary>Worker is running and accepting work assignments.</summary>
    Running = 3,

    /// <summary>Worker reported a status or completed work.</summary>
    Working = 4,

    /// <summary>Worker is shutting down cleanly.</summary>
    ShuttingDown = 5,

    /// <summary>Worker exited cleanly.</summary>
    Exited = 6,

    /// <summary>Worker crashed or was terminated by the OS.</summary>
    Failed = 7,

    /// <summary>Worker was killed by the supervisor (timeout, invalid state).</summary>
    Killed = 8,
}

/// <summary>
/// Desktop generation counter. Incremented on lock/logout/user switch/worker
/// restart to invalidate stale work. The supervisor tracks this to ensure no
/// stale reuse of worker state on unlock.
///
/// Generations never wrap: at <see cref="MaxValue"/> the counter is exhausted
/// and callers must fence/stop and block restart rather than reuse generation 0
/// or any earlier value.
/// </summary>
public readonly record struct DesktopGeneration
{
    /// <summary>Initial generation.</summary>
    public const uint Initial = 1;

    /// <summary>Maximum generation. Exhaustion fences and blocks restart.</summary>
    public const uint MaxValue = uint.MaxValue;

    public required uint Value { get; init; }

    /// <summary>
    /// Advance to the next generation. Returns false at <see cref="MaxValue"/>;
    /// callers must fence/stop and block restart instead of wrapping.
    /// </summary>
    public bool TryNext(out DesktopGeneration next)
    {
        if (Value >= MaxValue)
        {
            next = this;
            return false;
        }

        next = new DesktopGeneration { Value = Value + 1 };
        return true;
    }

    /// <summary>True when no further generation can be issued.</summary>
    public bool IsExhausted => Value >= MaxValue;

    public bool IsStale(DesktopGeneration current) => Value < current.Value;
}

/// <summary>
/// Worker identity information tracked by the supervisor. Captures the
/// OS-level identity of the worker process for the current generation.
/// </summary>
public readonly record struct WorkerIdentity
{
    /// <summary>Worker process ID.</summary>
    public required uint ProcessId { get; init; }

    /// <summary>Worker WTS session ID.</summary>
    public required uint SessionId { get; init; }

    /// <summary>Worker token user SID string.</summary>
    public required string TokenSid { get; init; }

    /// <summary>Desktop generation when this worker was started.</summary>
    public required DesktopGeneration Generation { get; init; }

    /// <summary>UTC timestamp when the worker was started.</summary>
    public required DateTimeOffset StartedAt { get; init; }

    /// <summary>
    /// Random launch ID for this specific worker instance. Used to fence
    /// stale callbacks from previous worker launches. 16 bytes of randomness.
    /// </summary>
    public required byte[] LaunchId { get; init; }
}

/// <summary>
/// Random identifiers for fencing stale callbacks. The boot ID persists for
/// the lifetime of the supervisor process. Each worker launch gets a unique
/// launch ID. Old callbacks that carry a stale boot or launch ID are rejected.
/// </summary>
public readonly record struct FencingIds
{
    /// <summary>Length of fencing ID bytes.</summary>
    public const int IdLength = 16;

    /// <summary>
    /// Boot ID: generated once when the supervisor is created. Persists
    /// across worker restarts. Old observer callbacks from a previous
    /// supervisor instance are rejected.
    /// </summary>
    public required byte[] BootId { get; init; }

    /// <summary>
    /// Launch ID: generated fresh for each worker launch. Old callbacks
    /// from a previous worker are rejected.
    /// </summary>
    public required byte[] LaunchId { get; init; }

    /// <summary>
    /// Generate a fresh random fencing ID.
    /// </summary>
    public static byte[] GenerateId()
    {
        byte[] id = new byte[IdLength];
        System.Security.Cryptography.RandomNumberGenerator.Fill(id);
        return id;
    }

    /// <summary>
    /// Check if a boot ID matches (same supervisor instance). Zero or
    /// wrong-length IDs never match.
    /// </summary>
    public bool MatchesBoot(byte[]? other)
    {
        if (!IsUsableId(BootId) || !IsUsableId(other)) return false;
        int diff = 0;
        for (int i = 0; i < IdLength; i++) diff |= BootId[i] ^ other![i];
        return diff == 0;
    }

    /// <summary>
    /// Check if a launch ID matches (same worker instance). Zero or
    /// wrong-length IDs never match.
    /// </summary>
    public bool MatchesLaunch(byte[]? other)
    {
        if (!IsUsableId(LaunchId) || !IsUsableId(other)) return false;
        int diff = 0;
        for (int i = 0; i < IdLength; i++) diff |= LaunchId[i] ^ other![i];
        return diff == 0;
    }

    /// <summary>
    /// An ID is usable only at exactly <see cref="IdLength"/> bytes and not
    /// all-zero. A zero ID is never a real generated fence.
    /// </summary>
    public static bool IsUsableId(byte[]? id)
    {
        if (id is null || id.Length != IdLength) return false;
        int acc = 0;
        for (int i = 0; i < id.Length; i++) acc |= id[i];
        return acc != 0;
    }
}

/// <summary>
/// Supervisor status. Reflects the overall state of the worker lifecycle
/// management. Exposed to the Computer app UI.
/// </summary>
public enum SupervisorStatus
{
    /// <summary>Supervisor is idle, no worker process.</summary>
    Idle = 0,

    /// <summary>Supervisor is starting a worker process.</summary>
    StartingWorker = 1,

    /// <summary>Worker is connected and running.</summary>
    WorkerRunning = 2,

    /// <summary>Worker crashed; supervisor is recovering.</summary>
    WorkerFailed = 3,

    /// <summary>Session is locked; work is paused.</summary>
    SessionLocked = 4,

    /// <summary>Session is eligible but no worker started (not enrolled).</summary>
    NotEnrolled = 5,

    /// <summary>Physical console is not eligible.</summary>
    ConsoleNotEligible = 6,

    /// <summary>Desktop generation changed; worker invalidated.</summary>
    GenerationInvalidated = 7,
}

/// <summary>
/// Supervisor event for logging and status tracking. No secrets, SIDs, or
/// host paths in the event text.
/// </summary>
public sealed record SupervisorEvent
{
    public required DateTimeOffset Timestamp { get; init; }
    public required SupervisorStatus Status { get; init; }
    public required string Description { get; init; }
    public WorkerStatus? WorkerStatus { get; init; }
    public DesktopGeneration? Generation { get; init; }
}

/// <summary>
/// Configuration for the worker process. Passed from supervisor to worker
/// at launch time via the IPC channel (not argv or environment).
/// </summary>
public sealed record WorkerLaunchConfig
{
    /// <summary>Pipe name for IPC communication.</summary>
    public required string PipeName { get; init; }

    /// <summary>Capability nonce for IPC authentication.</summary>
    public required byte[] CapabilityNonce { get; init; }

    /// <summary>Desktop generation for this launch.</summary>
    public required DesktopGeneration Generation { get; init; }

    /// <summary>Maximum worker lifetime before forced restart.</summary>
    public required TimeSpan MaxLifetime { get; init; }

    /// <summary>Heartbeat interval for liveness checks.</summary>
    public required TimeSpan HeartbeatInterval { get; init; }
}