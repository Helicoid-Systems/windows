using Helicoid.Domain.Setup;

namespace Helicoid.Domain.Setup;

/// <summary>
/// Windows manager guided server setup. Routes are Windows local and Linux SSH
/// only. The install backend is explicitly unimplemented; the wizard never
/// claims host writes it did not perform.
/// </summary>
public sealed class SetupWizard
{
    private readonly List<HostCheckRow> _hostChecks = new();

    public SetupWizard()
    {
        // Windows manager availability table from W17.
        AvailableRoutes = new[] { HostingRoute.WindowsLocal, HostingRoute.LinuxSsh };
    }

    public IReadOnlyList<HostingRoute> AvailableRoutes { get; }

    public HostingRoute? SelectedRoute { get; private set; }

    /// <summary>
    /// SSH address retained for the selected Linux route. This build never
    /// connects or verifies it, but the wizard must not claim the value was
    /// collected without using it.
    /// </summary>
    public string SshAddress { get; private set; } = string.Empty;

    public SetupStep CurrentStep { get; private set; } = SetupStep.ChooseHosting;

    public SetupBackendState BackendState { get; private set; } = SetupBackendState.NotStarted;

    public IReadOnlyList<HostCheckRow> HostChecks => _hostChecks;

    /// <summary>
    /// True only while the wizard is on Server Ready for Enrollment. Leaving
    /// that step (including GoBack) clears readiness by construction. Never
    /// Deployment Verified.
    /// </summary>
    public bool IsReadyForEnrollment => CurrentStep == SetupStep.Ready;

    /// <summary>Deployment Verified requires separate real endpoint evidence (H13/V39).</summary>
    public bool IsDeploymentVerified { get; private set; }

    public void SelectRoute(HostingRoute route)
    {
        if (!AvailableRoutes.Contains(route))
        {
            throw new ArgumentOutOfRangeException(
                nameof(route),
                route,
                "Windows manager offers only Windows local and Linux SSH hosting.");
        }

        SelectedRoute = route;
        CurrentStep = route == HostingRoute.WindowsLocal
            ? SetupStep.LocalHost
            : SetupStep.SshConnect;
        SshAddress = string.Empty;
        BackendState = SetupBackendState.NotStarted;
        _hostChecks.Clear();
        IsDeploymentVerified = false;
    }

    /// <summary>
    /// Record the SSH address for the selected Linux route. The value only
    /// gates progress into the host-identity step; this build makes no
    /// connection and verifies neither the address nor the host key.
    /// </summary>
    public void SetSshAddress(string? address)
    {
        SshAddress = address?.Trim() ?? string.Empty;
    }

    /// <summary>Step order after the route-specific prefix (H05 through H12).</summary>
    public IReadOnlyList<SetupStep> RemainingSteps()
    {
        if (SelectedRoute is null)
        {
            return Array.Empty<SetupStep>();
        }

        return SelectedRoute.Value switch
        {
            HostingRoute.WindowsLocal => new[]
            {
                SetupStep.CheckHost, SetupStep.Network, SetupStep.DeploymentIdentity,
                SetupStep.Administrator, SetupStep.Storage, SetupStep.Review,
                SetupStep.Install, SetupStep.Ready,
            },
            HostingRoute.LinuxSsh => new[]
            {
                SetupStep.SshHostIdentity, SetupStep.CheckHost, SetupStep.Network,
                SetupStep.DeploymentIdentity, SetupStep.Administrator, SetupStep.Storage,
                SetupStep.Review, SetupStep.Install, SetupStep.Ready,
            },
            _ => Array.Empty<SetupStep>(),
        };
    }

    /// <summary>
    /// Ordered steps for the selected route, including its route-specific
    /// entry step. Empty until a route is selected.
    /// </summary>
    public IReadOnlyList<SetupStep> RouteSteps()
    {
        if (SelectedRoute is null)
        {
            return Array.Empty<SetupStep>();
        }

        return SelectedRoute.Value switch
        {
            HostingRoute.WindowsLocal => new[]
            {
                SetupStep.LocalHost, SetupStep.CheckHost, SetupStep.Network,
                SetupStep.DeploymentIdentity, SetupStep.Administrator, SetupStep.Storage,
                SetupStep.Review, SetupStep.Install, SetupStep.Ready,
            },
            HostingRoute.LinuxSsh => new[]
            {
                SetupStep.SshConnect, SetupStep.SshHostIdentity, SetupStep.CheckHost,
                SetupStep.Network, SetupStep.DeploymentIdentity, SetupStep.Administrator,
                SetupStep.Storage, SetupStep.Review, SetupStep.Install, SetupStep.Ready,
            },
            _ => Array.Empty<SetupStep>(),
        };
    }

    /// <summary>True when a previous route step exists.</summary>
    public bool CanGoBack => StepIndex() > 0;

    /// <summary>
    /// True exactly when <see cref="TryAdvance"/> can move to the next route
    /// step. Only the two route entry transitions are implemented; Check Host
    /// and every later step stay closed because Network through Review remain
    /// unavailable. SSH host identity still has no verifier in this tree.
    /// </summary>
    public bool CanAdvance
    {
        get
        {
            var steps = RouteSteps();
            var index = StepIndex();
            if (index < 0 || index + 1 >= steps.Count)
            {
                return false;
            }

            var next = steps[index + 1];
            return CurrentStep switch
            {
                SetupStep.LocalHost => IsStepAvailable(next),
                SetupStep.SshConnect => SshAddress.Length > 0 && IsStepAvailable(next),
                _ => false,
            };
        }
    }

    /// <summary>
    /// Move to the next route step when this build has honest evidence for it.
    /// The policy is the same one exposed by <see cref="CanAdvance"/>; Ready is
    /// never entered without a real succeeded install.
    /// </summary>
    public bool TryAdvance()
    {
        if (!CanAdvance)
        {
            return false;
        }

        var steps = RouteSteps();
        CurrentStep = steps[StepIndex() + 1];
        return true;
    }

    /// <summary>Move to the previous route step. Returns false at the entry step.</summary>
    public bool GoBack()
    {
        var index = StepIndex();
        if (index <= 0)
        {
            return false;
        }

        CurrentStep = RouteSteps()[index - 1];
        return true;
    }

    /// <summary>Clear route, checks, install state, and readiness for a fresh start.</summary>
    public void Reset()
    {
        _hostChecks.Clear();
        SelectedRoute = null;
        CurrentStep = SetupStep.ChooseHosting;
        SshAddress = string.Empty;
        BackendState = SetupBackendState.NotStarted;
        IsDeploymentVerified = false;
    }

    private int StepIndex() => IndexOf(RouteSteps(), CurrentStep);

    /// <summary>
    /// Advance through the real gates to a later route step. This method does
    /// not jump over unavailable or incomplete steps; if the route cannot reach
    /// the target, the wizard stays on its original step and the call throws.
    /// </summary>
    public void AdvanceTo(SetupStep step)
    {
        if (SelectedRoute is null)
        {
            throw new InvalidOperationException("Select a hosting route first.");
        }

        var steps = RouteSteps();
        var targetIndex = IndexOf(steps, step);
        if (targetIndex < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(step),
                step,
                "Step is not part of the selected hosting route.");
        }

        if (!IsStepAvailable(step))
        {
            throw new InvalidOperationException(
                $"The {step} step is not available in this build.");
        }

        if (step == SetupStep.Ready && BackendState != SetupBackendState.Succeeded)
        {
            throw new InvalidOperationException(
                "Server Ready for Enrollment requires a succeeded install backend.");
        }

        var currentIndex = StepIndex();
        if (targetIndex < currentIndex)
        {
            throw new InvalidOperationException(
                "AdvanceTo cannot move to an earlier setup step.");
        }

        var originalStep = CurrentStep;
        while (StepIndex() < targetIndex)
        {
            if (!TryAdvance())
            {
                CurrentStep = originalStep;
                throw new InvalidOperationException(
                    $"The {step} step cannot be entered while a prerequisite step is incomplete or unavailable.");
            }
        }
    }

    private static int IndexOf(IReadOnlyList<SetupStep> steps, SetupStep step)
    {
        for (var i = 0; i < steps.Count; i++)
        {
            if (steps[i] == step)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Whether this build has an implementation for the step. Network through
    /// Review remain unavailable, so no gate may advance into them.
    /// </summary>
    private static bool IsStepAvailable(SetupStep step) => step
        is not (SetupStep.Network
            or SetupStep.DeploymentIdentity
            or SetupStep.Administrator
            or SetupStep.Storage
            or SetupStep.Review);

    /// <summary>
    /// Seed host-check rows for the Check Host step. The install backend is
    /// unimplemented, so rows report Unimplemented rather than inventing
    /// Passed results.
    /// </summary>
    public void SeedUnimplementedHostChecks()
    {
        _hostChecks.Clear();
        _hostChecks.Add(new HostCheckRow(
            "Operating system and architecture",
            CheckResult.Unimplemented));
        _hostChecks.Add(new HostCheckRow(
            "Privileges and install scope",
            CheckResult.Unimplemented));
        _hostChecks.Add(new HostCheckRow(
            "Disk, path, port, and service conflicts",
            CheckResult.Unimplemented));
        _hostChecks.Add(new HostCheckRow(
            "Existing installation",
            CheckResult.Unimplemented));
        BackendState = SetupBackendState.Unimplemented;
    }

    /// <summary>
    /// Attempt install. This tree has no host-writing backend; the result is
    /// honest Unimplemented, not a simulated success.
    /// </summary>
    public SetupBackendState AttemptInstall()
    {
        BackendState = SetupBackendState.Unimplemented;
        return BackendState;
    }

    /// <summary>
    /// Deployment Verified is separate later evidence. It cannot be set from
    /// wizard completion or a TCP probe.
    /// </summary>
    public void RecordDeploymentVerifiedEvidence()
    {
        if (!IsReadyForEnrollment)
        {
            throw new InvalidOperationException(
                "Server Ready for Enrollment must precede Deployment Verified.");
        }

        // Requires one real enrolled authorized endpoint with authorized media,
        // denial, teardown, and recovery evidence (H13/V39). Not available here.
        IsDeploymentVerified = false;
    }
}
