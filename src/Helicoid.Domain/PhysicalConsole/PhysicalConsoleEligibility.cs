namespace Helicoid.Domain.PhysicalConsole;

/// <summary>
/// Why a physical-console observation is or is not eligible for independently
/// permitted capture/input under D26. Eligible is a diagnostic classification
/// only; it is not admission, capture authority, or enrollment.
/// </summary>
public enum PhysicalConsoleDenialReason
{
    /// <summary>
    /// All checks passed. Diagnostic classification only — not admitted,
    /// capture-authorized, or enrolled.
    /// </summary>
    Eligible = 0,

    /// <summary>WTS query failed in either observation pass.</summary>
    ApiUnavailable = 1,

    /// <summary>WTSGetActiveConsoleSessionId reported no attached console.</summary>
    NoConsoleSessionAttached = 2,

    /// <summary>Selected physical-console session is session 0.</summary>
    SessionZero = 3,

    /// <summary>Observed fields changed between the two passes.</summary>
    ObservationUnstable = 4,

    /// <summary>Desktop query failed; input desktop cannot be established.</summary>
    DesktopQueryFailed = 5,

    /// <summary>Connect state is not WTSActive.</summary>
    ConnectStateNotActive = 6,

    /// <summary>Connect state is outside the known WTS_CONNECTSTATE_CLASS range.</summary>
    UnknownConnectState = 7,

    /// <summary>Session protocol is not the physical console (RDP or legacy).</summary>
    ProtocolNotConsole = 8,

    /// <summary>Session protocol value is outside the known WTSClientProtocolType range.</summary>
    UnknownProtocolType = 9,

    /// <summary>Current process is not running in the selected physical-console session.</summary>
    ProcessSessionMismatch = 10,

    /// <summary>Input desktop is missing or empty.</summary>
    DesktopMissing = 11,

    /// <summary>Input desktop is a protected surface (Winlogon / secure).</summary>
    DesktopProtected = 12,

    /// <summary>Input desktop is not the ordinary Default user desktop.</summary>
    DesktopNotDefault = 13,

    /// <summary>Session is locked (WTS_SESSIONSTATE_LOCK).</summary>
    SessionLocked = 14,

    /// <summary>Session lock state is unknown (WTS_SESSIONSTATE_UNKNOWN).</summary>
    UnknownLockState = 15,

    /// <summary>WTSSessionInfoEx lock query failed, or returned missing / malformed header data.</summary>
    LockQueryFailed = 16,
}

/// <summary>
/// Diagnostic eligibility classification for one physical-console observation.
/// </summary>
public sealed record PhysicalConsoleEligibility(
    bool IsEligible,
    PhysicalConsoleDenialReason Reason,
    PhysicalConsoleObservation Observation)
{
    public static PhysicalConsoleEligibility Eligible(PhysicalConsoleObservation observation) =>
        new(true, PhysicalConsoleDenialReason.Eligible, observation);

    public static PhysicalConsoleEligibility Denied(
        PhysicalConsoleDenialReason reason,
        PhysicalConsoleObservation observation)
    {
        if (reason == PhysicalConsoleDenialReason.Eligible)
        {
            throw new ArgumentOutOfRangeException(nameof(reason), "Denied requires a non-Eligible reason.");
        }

        return new PhysicalConsoleEligibility(false, reason, observation);
    }
}
