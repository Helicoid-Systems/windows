using Helicoid.Domain.Agent;
using Helicoid.Domain.Engine;
using Helicoid.Domain.Fixtures;
using Helicoid.Domain.Setup;
using Xunit;

namespace Helicoid.Domain.Tests;

public class AgentStatusTests
{
    [Fact]
    public void UserHasNoStopControlCommand()
    {
        var status = new AgentStatus();
        status.SetConnection(AgentConnectionState.Connected);
        status.SetControllingOperator("Morgan");

        Assert.False(status.UserCanStopControl);
        Assert.DoesNotContain("Stop Control", status.AvailableUserCommands());
        Assert.Equal("Morgan is controlling this computer", status.StatusSummary());
    }

    [Fact]
    public void MultipleObservers_AreListedWithCountSummary()
    {
        var status = new AgentStatus();
        status.SetConnection(AgentConnectionState.Connected);
        status.SetObservers(new[] { "Alex", "Sam" });

        Assert.Equal(2, status.Observers.Count);
        Assert.Equal("Your screen is being viewed by 2 operators", status.StatusSummary());
    }

    [Fact]
    public void SingleObserver_NamesTheOperator()
    {
        var status = new AgentStatus();
        status.SetConnection(AgentConnectionState.Connected);
        status.SetObservers(new[] { "Morgan" });

        Assert.Equal("Your screen is being viewed by Morgan", status.StatusSummary());
    }

    [Fact]
    public void ConnectedWithNoAccess_ReportsHonestIdleState()
    {
        var status = new AgentStatus();
        status.SetConnection(AgentConnectionState.Connected);

        Assert.Equal("Connected. No active screen access", status.StatusSummary());
        Assert.False(status.HasActiveScreenAccess);
    }

    [Fact]
    public void PendingApproval_ShowsWithoutPrematureMonitoring()
    {
        var status = new AgentStatus();
        status.SetConnection(AgentConnectionState.PendingApproval);

        Assert.Equal("Waiting for administrator approval", status.StatusSummary());
        Assert.Empty(status.AvailableUserCommands());
    }
}

public class RemoteEngineStatusTests
{
    [Fact]
    public void ThisBuild_ReportsUnavailableWithoutGuessingAbi()
    {
        var status = RemoteEngineStatus.UnavailableNoBridge();

        Assert.False(status.IsAvailable);
        Assert.Equal(RemoteEngineAvailability.Unavailable, status.Availability);
        Assert.Contains("not available", status.Reason);
        Assert.DoesNotContain("rustdesk_start", status.Reason);
    }
}

public class DevelopmentFixtureModeTests
{
    [Fact]
    public void FixturesAreOffByDefault()
    {
        var mode = new DevelopmentFixtureMode();

        Assert.False(mode.IsEnabled);
        Assert.Empty(mode.BuildInventoryOrEmpty());
        Assert.Contains("no fixtures", mode.Label);
    }

    [Fact]
    public void EnabledFixtures_AreLabeledAsSampleData()
    {
        var mode = new DevelopmentFixtureMode();
        mode.Enable();

        var inventory = mode.BuildInventoryOrEmpty();

        Assert.NotEmpty(inventory);
        Assert.Contains("Development fixtures", mode.Label);
        Assert.Contains("sample data", DevelopmentFixtures.FixtureLabel);
        Assert.All(inventory, c => Assert.StartsWith("fixture-", c.Id.Value));
    }

    [Fact]
    public void Disable_ClearsFixtureInventory()
    {
        var mode = new DevelopmentFixtureMode();
        mode.Enable();
        mode.Disable();

        Assert.Empty(mode.BuildInventoryOrEmpty());
    }
}
