using Helicoid.Computer.ViewModels;
using Helicoid.Domain.Agent;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Portable Computer presentation seams. Native WinUI is not exercised here;
/// these lock truthful labels and details-toggle behavior only.
/// </summary>
public class ComputerPresentationTests
{
    [Fact]
    public void DefaultIsNotEnrolled_AndNeverClaimsConnectedOrReady()
    {
        var vm = new AgentStatusViewModel();

        Assert.Equal("Not enrolled", vm.ConnectionSummary);
        Assert.Equal(string.Empty, vm.AccessHeadline);
        Assert.False(vm.HasAccessHeadline);
        Assert.DoesNotContain("Connected", vm.ConnectionSummary);
        Assert.DoesNotContain("Ready", vm.ConnectionSummary);
    }

    [Fact]
    public void UnknownConnection_NeverClaimsConnectedOrReady()
    {
        var vm = new AgentStatusViewModel();
        // Force an out-of-enum value through the honest fallback path.
        vm.Status.SetConnection((AgentConnectionState)99);

        Assert.Equal("Unknown", vm.ConnectionSummary);
        Assert.DoesNotContain("Connected", vm.ConnectionSummary);
        Assert.DoesNotContain("Ready", vm.ConnectionSummary);
    }

    [Fact]
    public void PendingApproval_SingleConnectionLineWithoutDuplicateAccess()
    {
        var vm = new AgentStatusViewModel();
        vm.SetConnection(AgentConnectionState.PendingApproval);

        Assert.Equal("Waiting for administrator approval", vm.ConnectionSummary);
        Assert.Equal(string.Empty, vm.AccessHeadline);
    }

    [Fact]
    public void ConnectedWithNoAccess_ReportsHonestIdleOnce()
    {
        var vm = new AgentStatusViewModel();
        vm.SetConnection(AgentConnectionState.Connected);

        Assert.Equal("Connected to Helicoid server", vm.ConnectionSummary);
        Assert.Equal("No active screen access", vm.AccessHeadline);
    }

    [Fact]
    public void NeedsPermissions_UsesWindowsHonestCopy_NotMacPermissionName()
    {
        var vm = new AgentStatusViewModel();
        vm.SetConnection(AgentConnectionState.NeedsPermissions);

        Assert.Equal("Screen Access Unavailable", vm.ConnectionSummary);
        Assert.DoesNotContain("Screen recording", vm.ConnectionSummary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("permission", vm.ConnectionSummary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ObserverAndControllerHeadlines_UseActualOperatorFacts()
    {
        var vm = new AgentStatusViewModel();
        vm.SetConnection(AgentConnectionState.Connected);
        vm.SetControllingOperator("Morgan");
        vm.SetObservers(new[] { "Alex", "Sam" });

        Assert.Equal("Morgan is controlling this computer", vm.AccessHeadline);

        vm.SetControllingOperator(null);
        Assert.Equal("Your screen is being viewed by 2 operators", vm.AccessHeadline);

        vm.SetObservers(new[] { "Alex" });
        Assert.Equal("Your screen is being viewed by Alex", vm.AccessHeadline);
    }

    [Fact]
    public void NoStopControlCommand_OnPresentationSurface()
    {
        var vm = new AgentStatusViewModel();
        vm.SetConnection(AgentConnectionState.Connected);
        vm.SetControllingOperator("Morgan");

        Assert.False(vm.ShowsStopControl);
        Assert.DoesNotContain("Stop Control", vm.UserCommands);
        Assert.Contains("no Stop Control", vm.StopControlNote);
    }

    [Fact]
    public void HelpStaysUnavailable_UntilRealTransportExists()
    {
        var vm = new AgentStatusViewModel();

        Assert.False(vm.CanRequestHelp);
    }

    [Fact]
    public void ViewDetails_TogglesRealDetailsAndNotifies()
    {
        var vm = new AgentStatusViewModel();
        Assert.False(vm.IsDetailsExpanded);
        Assert.Equal("View Details", vm.ViewDetailsLabel);

        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.IsDetailsExpanded = true;

        Assert.True(vm.IsDetailsExpanded);
        Assert.Equal("Hide Details", vm.ViewDetailsLabel);
        Assert.Contains(nameof(AgentStatusViewModel.IsDetailsExpanded), changed);
        Assert.Contains(nameof(AgentStatusViewModel.ViewDetailsLabel), changed);

        vm.IsDetailsExpanded = false;
        Assert.False(vm.IsDetailsExpanded);
    }

    [Fact]
    public void ModelChanges_RaisePresentationNotifications()
    {
        var vm = new AgentStatusViewModel();
        var seen = new List<string?>();
        vm.PropertyChanged += (_, e) => seen.Add(e.PropertyName);

        vm.SetConnection(AgentConnectionState.Connected);

        Assert.Contains(nameof(AgentStatusViewModel.ConnectionSummary), seen);
        Assert.Contains(nameof(AgentStatusViewModel.AccessHeadline), seen);
    }

    [Fact]
    public void DetailsWithoutSupervisor_AreHonestPlaceholders()
    {
        var vm = new AgentStatusViewModel();

        Assert.Equal("No supervisor", vm.SupervisorStatusSummary);
        Assert.Equal("No worker", vm.WorkerStatusSummary);
        Assert.Equal(0u, vm.DesktopGeneration);
        Assert.Null(vm.FailureNote);
        Assert.False(vm.HasFailureNote);
    }
}
