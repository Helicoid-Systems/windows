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

    public SetupStep CurrentStep { get; private set; } = SetupStep.ChooseHosting;

    public SetupBackendState BackendState { get; private set; } = SetupBackendState.NotStarted;

    public IReadOnlyList<HostCheckRow> HostChecks => _hostChecks;

    /// <summary>True once Server Ready for Enrollment is reached. Never Deployment Verified.</summary>
    public bool IsReadyForEnrollment { get; private set; }

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
        BackendState = SetupBackendState.NotStarted;
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

    public void AdvanceTo(SetupStep step)
    {
        if (SelectedRoute is null)
        {
            throw new InvalidOperationException("Select a hosting route first.");
        }

        CurrentStep = step;
        if (step == SetupStep.Ready)
        {
            IsReadyForEnrollment = true;
        }
    }

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
            CheckResult.Unimplemented,
            "This app cannot check the host yet."));
        _hostChecks.Add(new HostCheckRow(
            "Privileges and install scope",
            CheckResult.Unimplemented,
            "This app cannot check the host yet."));
        _hostChecks.Add(new HostCheckRow(
            "Disk, path, port, and service conflicts",
            CheckResult.Unimplemented,
            "This app cannot check the host yet."));
        _hostChecks.Add(new HostCheckRow(
            "Existing installation",
            CheckResult.Unimplemented,
            "This app cannot check the host yet."));
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
