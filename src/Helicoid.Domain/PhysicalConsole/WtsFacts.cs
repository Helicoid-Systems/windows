namespace Helicoid.Domain.PhysicalConsole;

/// <summary>
/// DWORD session identifier kept unsigned so the WTS "no attached console"
/// sentinel cannot wrap to a negative value through a silent cast.
/// </summary>
public readonly record struct WtsSessionId(uint Value)
{
    /// <summary>
    /// WTSGetActiveConsoleSessionId return when no session is attached to the
    /// physical console (for example during attach/detach transition).
    /// </summary>
    public const uint NoAttachedConsoleSentinel = 0xFFFFFFFF;

    public bool IsNoAttachedConsoleSentinel => Value == NoAttachedConsoleSentinel;

    public bool IsSessionZero => Value == 0u;

    public override string ToString() => Value.ToString();
}

/// <summary>
/// Named WTS_CONNECTSTATE_CLASS values. Unknown numeric values stay unknown
/// and are never coerced into a known state.
/// </summary>
public static class WtsConnectStateValues
{
    public const int Active = 0;
    public const int Connected = 1;
    public const int ConnectQuery = 2;
    public const int Shadow = 3;
    public const int Disconnected = 4;
    public const int Idle = 5;
    public const int Listen = 6;
    public const int Reset = 7;
    public const int Down = 8;
    public const int Init = 9;

    public static bool IsKnown(int value) => value is >= Active and <= Init;
}

/// <summary>
/// Named WTSClientProtocolType values. Protocol 0 is the physical console.
/// </summary>
public static class WtsProtocolTypeValues
{
    public const int Console = 0;
    public const int Legacy = 1;
    public const int Rdp = 2;

    public static bool IsKnown(int value) => value is >= Console and <= Rdp;
}

/// <summary>
/// WTS_SESSIONSTATE_* values for WTSINFOEX_LEVEL1_W.SessionFlags (LONG).
/// Windows 8 / 10 / 11 / Server 2012+ semantics only: 1 unlocks, 0 locks.
/// Windows 7 / Server 2008 R2 reversed these two values due to a documented
/// code defect and is not a supported target for this probe.
/// </summary>
public static class WtsSessionStateFlagValues
{
    /// <summary>WTS_SESSIONSTATE_UNLOCK: session is unlocked.</summary>
    public const int Unlock = 1;

    /// <summary>WTS_SESSIONSTATE_LOCK: session is locked.</summary>
    public const int Lock = 0;

    /// <summary>WTS_SESSIONSTATE_UNKNOWN (0xFFFFFFFF read as LONG).</summary>
    public const int Unknown = -1;
}

/// <summary>
/// Classified session lock state derived from WTS SessionFlags.
/// <see cref="Unknown"/> is the zero default so an unobserved or failed lock
/// query never appears unlocked.
/// </summary>
public enum WtsSessionLockState
{
    /// <summary>Lock state not established: query failed, missing, or unknown flag.</summary>
    Unknown = 0,

    /// <summary>WTS_SESSIONSTATE_LOCK: session is locked.</summary>
    Locked = 1,

    /// <summary>WTS_SESSIONSTATE_UNLOCK: session is explicitly unlocked.</summary>
    Unlocked = 2,
}
