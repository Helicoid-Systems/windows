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
