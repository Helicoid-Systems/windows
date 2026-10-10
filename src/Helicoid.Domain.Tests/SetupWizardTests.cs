using Helicoid.Domain.Client;
using Helicoid.Domain.Setup;
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
    public void ReadyForEnrollment_DoesNotMarkDeploymentVerified()
    {
        var wizard = new SetupWizard();
        wizard.SelectRoute(HostingRoute.WindowsLocal);
        wizard.AdvanceTo(SetupStep.Ready);

        Assert.True(wizard.IsReadyForEnrollment);
        Assert.False(wizard.IsDeploymentVerified);

        wizard.RecordDeploymentVerifiedEvidence();

        Assert.False(wizard.IsDeploymentVerified);
    }

    [Fact]
    public void CannotSelectUnsupportedRoute()
    {
        var wizard = new SetupWizard();
        Assert.Throws<ArgumentOutOfRangeException>(() => wizard.SelectRoute((HostingRoute)99));
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
