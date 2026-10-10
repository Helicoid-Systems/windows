using Helicoid.Domain.Model;
using Helicoid.Domain.Overview;
using Xunit;

namespace Helicoid.Domain.Tests;

public class OverviewStateTests
{
    private static readonly ComputerId A = ComputerId.Parse("pc-a");
    private static readonly ComputerId B = ComputerId.Parse("pc-b");
    private static readonly ComputerId C = ComputerId.Parse("pc-c");

    private static OverviewState NewState()
    {
        var state = new OverviewState();
        state.UpdateInventory(
            new[]
            {
                new ComputerRecord(A, "Alpha", ComputerStatus.Online, "ann"),
                new ComputerRecord(B, "Bravo", ComputerStatus.Offline),
                new ComputerRecord(C, "Charlie", ComputerStatus.NeedsAttention, "chris"),
            },
            new[] { A, B, C });
        return state;
    }

    [Fact]
    public void Selection_ClearsWhenSearchChanges()
    {
        var state = NewState();
        state.SelectOnly(A);
        Assert.Equal(1, state.Selection.Count);

        state.SetSearch("Alpha");

        Assert.Equal(0, state.Selection.Count);
    }

    [Fact]
    public void Selection_ClearsWhenStatusFilterChanges()
    {
        var state = NewState();
        state.SelectOnly(A);

        state.SetStatusFilter(StatusFilter.Online);

        Assert.Equal(0, state.Selection.Count);
    }

    [Fact]
    public void Selection_ClearsWhenInclusionChanges()
    {
        var state = NewState();
        state.SelectOnly(A);

        state.SetInclusion(MonitoringInclusion.Explicit(new[] { B }));

        Assert.Equal(0, state.Selection.Count);
    }

    [Fact]
    public void NoSelection_DefaultTargetsAreDisplayedFilteredIds()
    {
        var state = NewState();
        state.SetSearch("a"); // matches Alpha, Bravo, Charlie via names/users

        var targets = state.DefaultActionTargets;

        Assert.Equal(state.DisplayedIds, targets);
    }

    [Fact]
    public void WithSelection_DefaultTargetsAreOnlySelectedDisplayedIds()
    {
        var state = NewState();
        state.SelectOnly(A);
        state.Selection.Select(C);

        var targets = state.DefaultActionTargets;

        Assert.Equal(new[] { A, C }, targets.OrderBy(t => t.Value).ToArray());
    }

    [Fact]
    public void OpenAction_FreezesIdsAndInventoryChangesDoNotExpandThem()
    {
        var state = NewState();
        var snapshot = state.OpenAction("Message");

        state.UpdateInventory(
            new[]
            {
                new ComputerRecord(A, "Alpha", ComputerStatus.Online),
                new ComputerRecord(B, "Bravo", ComputerStatus.Online),
                new ComputerRecord(C, "Charlie", ComputerStatus.Online),
                new ComputerRecord(ComputerId.Parse("pc-d"), "Delta", ComputerStatus.Online),
            },
            new[] { A, B, C, ComputerId.Parse("pc-d") });

        Assert.Equal(3, snapshot.Count);
        Assert.Equal(new[] { A, B, C }, snapshot.ComputerIds);
    }

    [Fact]
    public void ZeroDisplayed_CannotOpenAction()
    {
        var state = NewState();
        state.SetSearch("no-such-computer");

        Assert.Throws<InvalidOperationException>(() => state.OpenAction("Message"));
    }

    [Fact]
    public void InclusionRemoval_StopsOverviewStream()
    {
        var state = NewState();
        state.UpsertAdmittedStream(A, "overview");
        state.UpsertAdmittedStream(B, "overview");

        state.OnInclusionRemoved(A);

        Assert.Single(state.AdmittedStreams);
        Assert.Equal(B, state.AdmittedStreams[0].ComputerId);
    }

    [Fact]
    public void Search_MatchesComputerNameAndTrustedUser()
    {
        var state = NewState();
        state.SetSearch("chris");
        Assert.Equal(new[] { C }, state.DisplayedIds);

        state.SetSearch("Bravo");
        Assert.Equal(new[] { B }, state.DisplayedIds);
    }

    [Fact]
    public void StatusFilter_Online_ExcludesOfflineAndNeedsAttention()
    {
        var state = NewState();
        state.SetStatusFilter(StatusFilter.Online);
        Assert.Equal(new[] { A }, state.DisplayedIds);
    }

    [Fact]
    public void RightClickUnselected_SelectsOnlyThatTile()
    {
        var state = NewState();
        state.SelectOnly(A);
        state.SelectOnly(B);
        Assert.Equal(new[] { B }, state.Selection.SelectedIds.ToArray());
    }
}

public class ActionSnapshotTests
{
    [Fact]
    public void Freeze_CapturesNamesAndIds()
    {
        var id = ComputerId.Parse("pc-1");
        var snapshot = ActionSnapshot.Freeze(
            "Send Files",
            new[] { (id, "PC-01") },
            DateTimeOffset.Parse("2026-10-10T12:00:00Z"));

        Assert.Equal("Send Files", snapshot.ActionName);
        Assert.Equal(1, snapshot.Count);
        Assert.Equal("PC-01", snapshot.DisplayNames[0]);
        Assert.Equal(DateTimeOffset.Parse("2026-10-10T12:00:00Z"), snapshot.CreatedAtUtc);
    }

    [Fact]
    public void Freeze_RequiresActionName()
    {
        Assert.Throws<ArgumentException>(() =>
            ActionSnapshot.Freeze("  ", new[] { (ComputerId.Parse("x"), "X") }));
    }
}
