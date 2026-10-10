namespace Helicoid.Domain.PhysicalConsole;

/// <summary>
/// Sanitized numeric facts from one WTS observation pass. Carries only session
/// numbers and raw enum integers. No usernames, domains, SIDs, host names,
/// memory addresses, pixels, or passwords.
/// </summary>
public readonly record struct ConsolePassFacts(
    WtsSessionId PhysicalConsoleSessionId,
    WtsSessionId ProcessSessionId,
    int ConnectState,
    int ProtocolType,
    bool WtsQuerySucceeded,
    WtsSessionLockState LockState = WtsSessionLockState.Unknown,
    bool LockQuerySucceeded = false)
{
    /// <summary>
    /// True when two passes observed identical relevant fields. Any difference
    /// is treated as an attachment/selection transition and denies eligibility.
    /// </summary>
    public bool Matches(in ConsolePassFacts other) =>
        PhysicalConsoleSessionId == other.PhysicalConsoleSessionId
        && ProcessSessionId == other.ProcessSessionId
        && ConnectState == other.ConnectState
        && ProtocolType == other.ProtocolType
        && WtsQuerySucceeded == other.WtsQuerySucceeded
        && LockState == other.LockState
        && LockQuerySucceeded == other.LockQuerySucceeded;
}

/// <summary>
/// Two-pass physical-console observation with the input-desktop category taken
/// between the passes. The second pass re-reads every relevant WTS field so a
/// change during the desktop query is refused as unstable rather than silently
/// accepted. Observation never manufactures a desktop generation from a WTS
/// session number.
/// </summary>
public sealed record PhysicalConsoleObservation(
    ConsolePassFacts FirstPass,
    ConsolePassFacts SecondPass,
    InputDesktopCategory DesktopCategory,
    bool DesktopQuerySucceeded)
{
    /// <summary>
    /// True when both passes observed the same relevant fields. A desktop query
    /// that failed or a changed field makes the whole observation unstable.
    /// </summary>
    public bool IsStable =>
        DesktopQuerySucceeded
        && FirstPass.Matches(SecondPass);
}
