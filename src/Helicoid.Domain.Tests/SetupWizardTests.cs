using Helicoid.Domain.Client;
using Helicoid.Domain.Setup;
using Helicoid.Manager.ViewModels;
using Xunit;

namespace Helicoid.Domain.Tests;

public class SetupWizardTests
{
    [Fact]
    public void WindowsManager_OffersExactlyWindowsLocalAndLinuxSsh()
    {
        var wizard = new SetupWizard();

        Assert.Equal(
            new[] { HostingRoute.WindowsLocal, HostingRoute.LinuxSsh },
            wizard.AvailableRoutes);
    }

    [Fact]
    public void WindowsLocal_RouteSequence_IsLocalHostThenH05ThroughH12()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);

        Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
        Assert.Equal(
            new[]
            {
                SetupStep.CheckHost, SetupStep.Network, SetupStep.DeploymentIdentity,
                SetupStep.Administrator, SetupStep.Storage, SetupStep.Review,
                SetupStep.Install, SetupStep.Ready,
            },
            wizard.RemainingSteps());
    }

    [Fact]
    public void LinuxSsh_RouteSequence_IncludesHostIdentity()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.LinuxSsh);

        Assert.Equal(SetupStep.SshConnect, wizard.CurrentStep);
        Assert.Contains(SetupStep.SshHostIdentity, wizard.RemainingSteps());
    }

    [Fact]
    public void InstallBackend_IsHonestUnimplemented()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);
        wizard.SeedUnimplementedHostChecks();

        var result = wizard.AttemptInstall();

        Assert.Equal(SetupBackendState.Unimplemented, result);
        Assert.All(wizard.HostChecks, row => Assert.Equal(CheckResult.Unimplemented, row.Result));
    }

    [Fact]
    public void ReadyForEnrollment_RequiresSucceededBackend_AndNeverMarksDeploymentVerified()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);

        var error = Assert.Throws<InvalidOperationException>(
            () => wizard.AdvanceTo(SetupStep.Ready));

        Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
        Assert.Contains("succeeded install", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(wizard.IsReadyForEnrollment);
        Assert.False(wizard.IsDeploymentVerified);

        Assert.Throws<InvalidOperationException>(
            () => wizard.RecordDeploymentVerifiedEvidence());
    }

    [Fact]
    public void CannotSelectUnsupportedRoute()
    {
        var wizard = new SetupWizard();
        Assert.Throws<ArgumentOutOfRangeException>(() => wizard.SelectRoute((HostingRoute)99));
    }

    [Fact]
    public void RouteSteps_IncludeRouteEntryAndSharedTail()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);
        Assert.Equal(
            new[]
            {
                SetupStep.LocalHost, SetupStep.CheckHost, SetupStep.Network,
                SetupStep.DeploymentIdentity, SetupStep.Administrator, SetupStep.Storage,
                SetupStep.Review, SetupStep.Install, SetupStep.Ready,
            },
            wizard.RouteSteps());

        wizard.SelectRoute(HostingRoute.LinuxSsh);
        Assert.Equal(
            new[]
            {
                SetupStep.SshConnect, SetupStep.SshHostIdentity, SetupStep.CheckHost,
                SetupStep.Network, SetupStep.DeploymentIdentity, SetupStep.Administrator,
                SetupStep.Storage, SetupStep.Review, SetupStep.Install, SetupStep.Ready,
            },
            wizard.RouteSteps());
    }

    [Fact]
    public void TryAdvance_AndGoBack_WalkTheRouteWithoutSkipping()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);

        Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
        Assert.False(wizard.CanGoBack);
        Assert.Equal(SetupStep.CheckHost, wizard.RouteSteps()[1]);

        Assert.True(wizard.TryAdvance());
        Assert.Equal(SetupStep.CheckHost, wizard.CurrentStep);
        Assert.True(wizard.CanGoBack);

        Assert.False(wizard.CanAdvance);
        Assert.False(wizard.TryAdvance());

        Assert.True(wizard.GoBack());
        Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
        Assert.False(wizard.GoBack());
    }

    [Fact]
    public void CheckHost_CannotAdvanceWithUnimplementedChecksIntoUnavailableNetworkStep()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);
        wizard.AdvanceTo(SetupStep.CheckHost);

        Assert.False(wizard.CanAdvance);
        Assert.False(wizard.TryAdvance());

        wizard.SeedUnimplementedHostChecks();

        Assert.All(wizard.HostChecks, row => Assert.Equal(CheckResult.Unimplemented, row.Result));
        Assert.False(wizard.CanAdvance);
        Assert.False(wizard.TryAdvance());
        Assert.Equal(SetupStep.CheckHost, wizard.CurrentStep);
    }

    [Fact]
    public void SeededUnimplementedHostCheck_ReadsAsNotVerifiedWithoutInventedDetail()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);
        wizard.SeedUnimplementedHostChecks();

        var actual = wizard.HostChecks.Single(row =>
            row.Name == "Disk, path, port, and service conflicts");
        var row = new SetupHostCheckRow(actual);

        Assert.Null(actual.Detail);
        Assert.Equal("Not verified", row.StateText);
        Assert.Equal(string.Empty, row.Detail);
        Assert.False(row.HasDetail);
    }

    [Fact]
    public void LinuxSshHostIdentity_CannotAdvanceWithoutAVerifier()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.LinuxSsh);
        wizard.SetSshAddress("ubuntu@server.example.com");
        wizard.AdvanceTo(SetupStep.SshHostIdentity);

        Assert.False(wizard.CanAdvance);
        Assert.False(wizard.TryAdvance());
        Assert.Equal(SetupStep.SshHostIdentity, wizard.CurrentStep);
    }

    [Fact]
    public void SshConnect_RequiresAStoredAddressBeforeAdvancing()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.LinuxSsh);

        Assert.False(wizard.CanAdvance);
        Assert.False(wizard.TryAdvance());
        Assert.Equal(SetupStep.SshConnect, wizard.CurrentStep);

        wizard.SetSshAddress("   ");
        Assert.Equal(string.Empty, wizard.SshAddress);
        Assert.False(wizard.CanAdvance);

        wizard.SetSshAddress("  ubuntu@server.example.com  ");
        Assert.Equal("ubuntu@server.example.com", wizard.SshAddress);
        Assert.True(wizard.CanAdvance);
        Assert.True(wizard.TryAdvance());
        Assert.Equal(SetupStep.SshHostIdentity, wizard.CurrentStep);
        Assert.False(wizard.CanAdvance);
    }

    [Fact]
    public void AdvanceTo_RejectsUnavailableStepsWithoutMoving()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);

        foreach (var step in new[]
                 {
                     SetupStep.Network, SetupStep.DeploymentIdentity,
                     SetupStep.Administrator, SetupStep.Storage, SetupStep.Review,
                 })
        {
            var error = Assert.Throws<InvalidOperationException>(
                () => wizard.AdvanceTo(step));

            Assert.Contains("not available", error.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
        }
    }

    [Fact]
    public void AdvanceTo_CannotSkipOverUnavailableStepsToInstall()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);

        var error = Assert.Throws<InvalidOperationException>(
            () => wizard.AdvanceTo(SetupStep.Install));

        Assert.Contains("prerequisite", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
        Assert.False(wizard.IsReadyForEnrollment);
    }

    [Fact]
    public void AdvanceTo_CannotMoveBackward()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);
        wizard.AdvanceTo(SetupStep.CheckHost);

        Assert.Throws<InvalidOperationException>(
            () => wizard.AdvanceTo(SetupStep.LocalHost));
        Assert.Equal(SetupStep.CheckHost, wizard.CurrentStep);
    }

    [Fact]
    public void GoBack_FromReady_ClearsReadyForEnrollment()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);

        // Ready is unreachable in this build because no install backend can
        // succeed. Set it directly to prove the GoBack invariant only.
        typeof(SetupWizard)
            .GetProperty(nameof(SetupWizard.CurrentStep))!
            .GetSetMethod(nonPublic: true)!
            .Invoke(wizard, new object[] { SetupStep.Ready });

        Assert.True(wizard.IsReadyForEnrollment);
        Assert.True(wizard.GoBack());
        Assert.Equal(SetupStep.Install, wizard.CurrentStep);
        Assert.False(wizard.IsReadyForEnrollment);
    }

    [Fact]
    public void AdvanceTo_RejectsAStepOutsideTheSelectedRoute()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.LinuxSsh);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => wizard.AdvanceTo(SetupStep.LocalHost));
        Assert.Equal(SetupStep.SshConnect, wizard.CurrentStep);
    }

    [Fact]
    public void Install_CannotBeReachedOrClaimReadyWithoutASucceededBackend()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);

        // Review and the steps before it are unavailable, so neither a direct
        // jump nor TryAdvance may reach Installation in this build.
        Assert.Throws<InvalidOperationException>(
            () => wizard.AdvanceTo(SetupStep.Install));
        Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
        Assert.False(wizard.IsReadyForEnrollment);

        Assert.Equal(SetupBackendState.Unimplemented, wizard.AttemptInstall());
        Assert.False(wizard.IsReadyForEnrollment);
        Assert.Throws<InvalidOperationException>(
            () => wizard.AdvanceTo(SetupStep.Install));
        Assert.Equal(SetupStep.LocalHost, wizard.CurrentStep);
    }

    [Fact]
    public void Reset_ReturnsToChooseHostingAndClearsState()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);
        wizard.SeedUnimplementedHostChecks();
        wizard.AdvanceTo(SetupStep.CheckHost);
        wizard.SetSshAddress("ubuntu@server.example.com");

        wizard.Reset();

        Assert.Null(wizard.SelectedRoute);
        Assert.Equal(SetupStep.ChooseHosting, wizard.CurrentStep);
        Assert.Empty(wizard.HostChecks);
        Assert.Empty(wizard.RouteSteps());
        Assert.Equal(string.Empty, wizard.SshAddress);
        Assert.Equal(SetupBackendState.NotStarted, wizard.BackendState);
        Assert.False(wizard.IsReadyForEnrollment);
        Assert.False(wizard.CanGoBack);
        Assert.False(wizard.CanAdvance);
    }
}

public class ClosedProductionClientTests
{
    [Fact]
    public async Task Connect_FailsClosed()
    {
        var client = new ClosedProductionClient();
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("user", "password-not-logged", "dev-identity", CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotAvailableInThisBuild, ex.Failure);
    }

    [Fact]
    public async Task Inventory_FailsClosed()
    {
        var client = new ClosedProductionClient();
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetInventoryAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotAvailableInThisBuild, ex.Failure);
        Assert.Contains("pending", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HasNoSession()
    {
        Assert.False(new ClosedProductionClient().HasSession);
    }
}
