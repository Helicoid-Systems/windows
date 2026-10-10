namespace Helicoid.Domain.PhysicalConsole;

/// <summary>
/// Pure eligibility policy for D26 physical-console selection. Native WTS and
/// desktop APIs stay outside this cross-platform domain; callers supply
/// sanitized observation facts and receive a deterministic classification.
/// Every path fails closed: sentinel, session 0, remote, protected, transition,
/// API failure, and unknown values all deny.
/// </summary>
public static class PhysicalConsoleEligibilityPolicy
{
    /// <summary>
    /// Classify one observation. Evaluation order is fixed so the first
    /// decisive denial is reported consistently.
    /// </summary>
    public static PhysicalConsoleEligibility Evaluate(PhysicalConsoleObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);

        // API failure in either pass: refuse before interpreting raw values.
        if (!observation.FirstPass.WtsQuerySucceeded || !observation.SecondPass.WtsQuerySucceeded)
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.ApiUnavailable,
                observation);
        }

        // Sentinel: no session attached to the physical console.
        if (observation.FirstPass.PhysicalConsoleSessionId.IsNoAttachedConsoleSentinel
            || observation.SecondPass.PhysicalConsoleSessionId.IsNoAttachedConsoleSentinel)
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.NoConsoleSessionAttached,
                observation);
        }

        // Session 0 is never an ordinary user desktop.
        if (observation.FirstPass.PhysicalConsoleSessionId.IsSessionZero
            || observation.SecondPass.PhysicalConsoleSessionId.IsSessionZero)
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.SessionZero,
                observation);
        }

        // Fields changed across the desktop query: attachment/selection transition.
        if (!observation.FirstPass.Matches(observation.SecondPass))
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.ObservationUnstable,
                observation);
        }

        // Desktop query must succeed before desktop classification is trusted.
        if (!observation.DesktopQuerySucceeded)
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.DesktopQueryFailed,
                observation);
        }

        // Connect state: known values first, then Active-only.
        int connectState = observation.FirstPass.ConnectState;
        if (!WtsConnectStateValues.IsKnown(connectState))
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.UnknownConnectState,
                observation);
        }

        if (connectState != WtsConnectStateValues.Active)
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.ConnectStateNotActive,
                observation);
        }

        // Protocol: known values first, then console-only (0). RDP and legacy deny.
        int protocolType = observation.FirstPass.ProtocolType;
        if (!WtsProtocolTypeValues.IsKnown(protocolType))
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.UnknownProtocolType,
                observation);
        }

        if (protocolType != WtsProtocolTypeValues.Console)
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.ProtocolNotConsole,
                observation);
        }

        // Process must already be in the selected physical-console session.
        if (observation.FirstPass.ProcessSessionId != observation.FirstPass.PhysicalConsoleSessionId)
        {
            return PhysicalConsoleEligibility.Denied(
                PhysicalConsoleDenialReason.ProcessSessionMismatch,
                observation);
        }

        // Desktop: only Default is an ordinary user desktop.
        switch (observation.DesktopCategory)
        {
            case InputDesktopCategory.Missing:
                return PhysicalConsoleEligibility.Denied(
                    PhysicalConsoleDenialReason.DesktopMissing,
                    observation);

            case InputDesktopCategory.Winlogon:
            case InputDesktopCategory.Secure:
                return PhysicalConsoleEligibility.Denied(
                    PhysicalConsoleDenialReason.DesktopProtected,
                    observation);

            case InputDesktopCategory.Default:
                return PhysicalConsoleEligibility.Eligible(observation);

            default:
                return PhysicalConsoleEligibility.Denied(
                    PhysicalConsoleDenialReason.DesktopNotDefault,
                    observation);
        }
    }
}
