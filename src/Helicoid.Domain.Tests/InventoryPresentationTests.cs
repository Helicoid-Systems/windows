using Helicoid.Domain.Client;
using Helicoid.Domain.Model;
using Helicoid.Domain.Overview;
using Helicoid.Manager.ViewModels;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Inventory presentation seam: filtered display, density/layout reflow
/// preserving selection, pause/resume session demand, tri-state inclusion,
/// and stale inventory load fencing.
/// </summary>
public class InventoryPresentationTests
{
    private static readonly ComputerId A = ComputerId.Parse("pc-a");
    private static readonly ComputerId B = ComputerId.Parse("pc-b");
    private static readonly ComputerId C = ComputerId.Parse("pc-c");
    private static readonly ComputerId D = ComputerId.Parse("pc-d");

    private static MainViewModel NewMain() =>
        new(DevelopmentLaunchOptions.Parse(Array.Empty<string>()));

    private static void ApplySample(MainViewModel main)
    {
        main.ApplyServerInventory(new[]
        {
            new ComputerRecord(A, "Alpha", ComputerStatus.Online, "ann"),
            new ComputerRecord(B, "Bravo", ComputerStatus.Offline),
            new ComputerRecord(C, "Charlie", ComputerStatus.NeedsAttention, "chris"),
            new ComputerRecord(D, "PC-2", ComputerStatus.Online),
        });
    }

    [Fact]
    public void FilteredPresentation_ShowsOnlyMatchingDisplayedTiles()
    {
        using var main = NewMain();
        ApplySample(main);

        main.OnSearchChanged("a");
        var names = main.Tiles.Select(t => t.Name).ToArray();
        Assert.Contains("Alpha", names);
        Assert.Contains("Bravo", names);
        Assert.Contains("Charlie", names);
        Assert.DoesNotContain("PC-2", names);

        main.OnSearchChanged("chris");
        Assert.Equal(new[] { "Charlie" }, main.Tiles.Select(t => t.Name).ToArray());

        main.OnStatusFilterChanged(StatusFilter.Online);
        // Search still "chris" → no online match.
        Assert.Empty(main.Tiles);
    }

    [Fact]
    public void NaturalNameOrder_UsesDigitRunsAndIdTieBreak()
    {
        using var main = NewMain();
        main.ApplyServerInventory(new[]
        {
            new ComputerRecord(A, "PC-10", ComputerStatus.Online),
            new ComputerRecord(B, "PC-2", ComputerStatus.Online),
            new ComputerRecord(C, "PC-2", ComputerStatus.Online),
            new ComputerRecord(D, "Alpha", ComputerStatus.Online),
        });

        var ids = main.Overview.DisplayedIds;
        Assert.Equal(new[] { D, B, C, A }, ids);
    }

    [Fact]
    public void DensityChange_PreservesSelectionFiltersAndInclusion()
    {
        using var main = NewMain();
        ApplySample(main);
        main.SetComputerIncluded(C, included: false);
        main.OnSearchChanged("a");
        main.SelectTile(A, additive: false);
        Assert.Equal(1, main.Overview.Selection.Count);

        main.PreviewSize = PreviewSize.Compact192;
        main.IsGridView = false;
        main.PreviewSize = PreviewSize.ExtraLarge448;

        Assert.Equal(1, main.Overview.Selection.Count);
        Assert.True(main.Overview.Selection.IsSelected(A));
        Assert.Equal("a", main.Overview.Filter.SearchQuery);
        Assert.False(main.Overview.Inclusion.Contains(C));
        Assert.Equal((int)PreviewSize.ExtraLarge448, main.PreviewSizePixels);
    }

    [Fact]
    public void DensityChange_DoesNotRebuildTileInstances()
    {
        using var main = NewMain();
        ApplySample(main);
        var before = main.Tiles.ToArray();

        main.PreviewSize = PreviewSize.Compact192;
        main.IsGridView = false;

        var after = main.Tiles.ToArray();
        Assert.Equal(before.Length, after.Length);
        for (var i = 0; i < before.Length; i++)
        {
            Assert.Same(before[i], after[i]);
        }

        Assert.All(after, t => Assert.Equal((int)PreviewSize.Compact192, t.PreviewExtent));
    }

    [Fact]
    public void PauseMonitoring_ClearsAdmittedStreamsAndBlocksNewOnes()
    {
        using var main = NewMain();
        ApplySample(main);
        main.Overview.UpsertAdmittedStream(A, "overview");
        main.Overview.UpsertAdmittedStream(B, "overview");
        Assert.Equal(2, main.Overview.AdmittedStreams.Count);

        main.PauseMonitoring();

        Assert.True(main.IsMonitoringPaused);
        Assert.Empty(main.Overview.AdmittedStreams);
        main.Overview.UpsertAdmittedStream(C, "overview");
        Assert.Empty(main.Overview.AdmittedStreams);
    }

    [Fact]
    public void ResumeMonitoring_RestoresDemandWithoutFabricatingStreams()
    {
        using var main = NewMain();
        ApplySample(main);
        main.Overview.UpsertAdmittedStream(A, "overview");
        main.PauseMonitoring();
        main.ResumeMonitoring();

        Assert.False(main.IsMonitoringPaused);
        Assert.Empty(main.Overview.AdmittedStreams);
        main.Overview.UpsertAdmittedStream(A, "overview");
        Assert.Single(main.Overview.AdmittedStreams);
    }

    [Fact]
    public void PauseResume_KeepsInventoryAndSelection()
    {
        using var main = NewMain();
        ApplySample(main);
        main.SelectTile(A, additive: false);

        main.PauseMonitoring();
        main.ResumeMonitoring();

        Assert.Equal(4, main.Tiles.Count);
        Assert.True(main.Overview.Selection.IsSelected(A));
    }

    [Fact]
    public void TriStateInclusion_CheckedIndeterminateUnchecked()
    {
        using var main = NewMain();
        ApplySample(main);
        var authorized = new[] { A, B, C, D };

        Assert.Equal(InclusionCheckState.Checked, main.GetAllComputersCheckState());

        main.SetComputerIncluded(D, included: false);
        Assert.Equal(InclusionCheckState.Indeterminate, main.GetAllComputersCheckState());
        Assert.False(main.Overview.Inclusion.Contains(D));
        Assert.True(main.Overview.Inclusion.Contains(A));

        main.SetComputerIncluded(A, included: false);
        main.SetComputerIncluded(B, included: false);
        main.SetComputerIncluded(C, included: false);
        Assert.Equal(InclusionCheckState.Unchecked, main.GetAllComputersCheckState());
    }

    [Fact]
    public void TriStateInclusion_NoOpCheckboxDoesNotLoop()
    {
        using var main = NewMain();
        ApplySample(main);

        // Already included under All mode: setting true is a no-op.
        var before = main.Overview.Inclusion.IsAllMode;
        main.SetComputerIncluded(A, included: true);
        Assert.Equal(before, main.Overview.Inclusion.IsAllMode);
        Assert.Equal(4, main.Tiles.Count);

        // Already excluded: setting false is a no-op.
        main.SetComputerIncluded(D, included: false);
        main.SetComputerIncluded(D, included: false);
        Assert.False(main.Overview.Inclusion.Contains(D));
        Assert.Equal(3, main.Tiles.Count);
    }

    [Fact]
    public void GroupCheckbox_TriStateAndSetMembers()
    {
        using var main = NewMain();
        main.ApplyServerInventory(new[]
        {
            new ComputerRecord(A, "Alpha", ComputerStatus.Online, null, "lab"),
            new ComputerRecord(B, "Bravo", ComputerStatus.Online, null, "lab"),
            new ComputerRecord(C, "Charlie", ComputerStatus.Online, null, "office"),
        });

        Assert.Equal(2, main.Groups.Count);
        var lab = main.Groups.First(g => g.Id == "lab");
        Assert.Equal(InclusionCheckState.Checked, main.GetGroupCheckState(lab.MemberIds));

        main.SetGroupIncluded(lab.MemberIds, included: false);
        Assert.Equal(InclusionCheckState.Unchecked, main.GetGroupCheckState(lab.MemberIds));
        Assert.Equal(new[] { C }, main.Tiles.Select(t => t.Id).ToArray());

        main.SetGroupIncluded(lab.MemberIds, included: true);
        Assert.Equal(InclusionCheckState.Checked, main.GetGroupCheckState(lab.MemberIds));
        Assert.Equal(3, main.Tiles.Count);
    }

    [Fact]
    public void EmptyStates_DifferInventoryNoInclusionNoMatches()
    {
        using var main = NewMain();

        main.RefreshInventory();
        Assert.Equal(InventoryEmptyKind.NoInventory, main.EmptyKind);

        ApplySample(main);
        Assert.Equal(InventoryEmptyKind.None, main.EmptyKind);

        main.Overview.Inclusion.ClearToEmptyExplicit();
        main.Overview.SetInclusion(main.Overview.Inclusion);
        Assert.Equal(InventoryEmptyKind.NoInclusion, main.EmptyKind);

        main.Overview.Inclusion.CheckAll();
        main.Overview.SetInclusion(main.Overview.Inclusion);
        main.OnSearchChanged("no-such-computer");
        Assert.Equal(InventoryEmptyKind.NoMatches, main.EmptyKind);
    }

    [Fact]
    public void StaleInventoryLoad_IsDroppedAndDoesNotReplace()
    {
        using var main = NewMain();
        ApplySample(main);

        var staleEpoch = main.BeginInventoryLoad();
        var freshEpoch = main.BeginInventoryLoad();
        Assert.NotEqual(staleEpoch, freshEpoch);

        var stalePayload = new[]
        {
            new ComputerRecord(ComputerId.Parse("pc-stale"), "Stale", ComputerStatus.Online),
        };
        Assert.False(main.TryCompleteInventoryLoad(staleEpoch, stalePayload));
        Assert.DoesNotContain(main.Tiles, t => t.Name == "Stale");

        var freshPayload = new[]
        {
            new ComputerRecord(ComputerId.Parse("pc-fresh"), "Fresh", ComputerStatus.Online),
        };
        Assert.True(main.TryCompleteInventoryLoad(freshEpoch, freshPayload));
        Assert.Equal(new[] { "Fresh" }, main.Tiles.Select(t => t.Name).ToArray());
    }

    [Fact]
    public void StaleInventoryLoad_AfterSessionClear_IsDropped()
    {
        using var main = NewMain();
        ApplySample(main);

        var epoch = main.BeginInventoryLoad();
        main.ClearSessionScopedInventory();

        Assert.Empty(main.Tiles);
        var late = new[]
        {
            new ComputerRecord(ComputerId.Parse("pc-late"), "Late", ComputerStatus.Online),
        };
        Assert.False(main.TryCompleteInventoryLoad(epoch, late));
        Assert.Empty(main.Tiles);
    }

    [Fact]
    public void ClearFilters_ClearsSearchAndStatusOnly()
    {
        using var main = NewMain();
        ApplySample(main);
        main.OnSearchChanged("a");
        main.OnStatusFilterChanged(StatusFilter.Online);
        main.SelectTile(A, additive: false);

        main.ClearFilters();

        Assert.Equal(string.Empty, main.Overview.Filter.SearchQuery);
        Assert.Equal(StatusFilter.All, main.Overview.Filter.StatusFilter);
        Assert.Equal(4, main.Tiles.Count);
    }

    [Fact]
    public void LaunchFixtures_RequireExplicitSwitch()
    {
        var off = DevelopmentLaunchOptions.Parse(Array.Empty<string>());
        Assert.False(off.DevelopmentFixturesEnabled);

        var on = DevelopmentLaunchOptions.Parse(new[] { "--development-fixtures" });
        Assert.True(on.DevelopmentFixturesEnabled);

        using var main = new MainViewModel(on);
        Assert.True(main.Fixtures.IsEnabled);
        Assert.NotEmpty(main.Tiles);
        Assert.Contains("sample data", main.Fixtures.Label);
    }

    [Fact]
    public void QuietTiles_NeverClaimLiveOrOnlineBadge()
    {
        using var main = NewMain();
        ApplySample(main);

        foreach (var tile in main.Tiles)
        {
            Assert.Equal("Screen Unavailable", tile.PreviewTitle);
            Assert.Contains("not available", tile.PreviewDetail, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Online", tile.ExceptionText ?? string.Empty);
        }
    }

    [Fact]
    public void ExcludeOnlyComputer_StillVisibleInPanelAndCanReinclude()
    {
        using var main = NewMain();
        main.ApplyServerInventory(new[]
        {
            new ComputerRecord(A, "Alpha", ComputerStatus.Online),
        });

        Assert.Single(main.Tiles);
        Assert.Single(main.AllAuthorizedTiles);

        main.SetComputerIncluded(A, included: false);

        // Displayed inventory drops the computer; inclusion panel keeps it.
        Assert.Empty(main.Tiles);
        Assert.Single(main.AllAuthorizedTiles);
        Assert.Equal(A, main.AllAuthorizedTiles[0].Id);
        Assert.False(main.AllAuthorizedTiles[0].IsIncludedInOverview);

        main.SetComputerIncluded(A, included: true);
        Assert.Single(main.Tiles);
        Assert.True(main.Tiles[0].IsIncludedInOverview);
    }

    [Fact]
    public void SearchHidesPreviewButNotInclusionPanel()
    {
        using var main = NewMain();
        ApplySample(main);

        main.OnSearchChanged("no-such");

        Assert.Empty(main.Tiles);
        Assert.Equal(4, main.AllAuthorizedTiles.Count);
        // Full authorized set stays ordered and reusable.
        Assert.Equal(new[] { "Alpha", "Bravo", "Charlie", "PC-2" },
            main.AllAuthorizedTiles.Select(t => t.Name).ToArray());
    }

    [Fact]
    public void AllClearAndRestore_ActualDisplayedCollection()
    {
        using var main = NewMain();
        ApplySample(main);

        main.ToggleAllIncludedFromClick();
        // Previous state was Checked -> empty explicit.
        Assert.Empty(main.Tiles);
        Assert.Equal(4, main.AllAuthorizedTiles.Count);
        Assert.Equal(InclusionCheckState.Unchecked, main.GetAllComputersCheckState());

        main.ToggleAllIncludedFromClick();
        // Previous state was Unchecked -> all.
        Assert.Equal(4, main.Tiles.Count);
        Assert.Equal(InclusionCheckState.Checked, main.GetAllComputersCheckState());
    }

    [Fact]
    public void AllClick_MixedPreviousState_IncludesAll()
    {
        using var main = NewMain();
        ApplySample(main);
        main.SetComputerIncluded(D, included: false);
        Assert.Equal(InclusionCheckState.Indeterminate, main.GetAllComputersCheckState());

        main.ToggleAllIncludedFromClick();

        Assert.Equal(InclusionCheckState.Checked, main.GetAllComputersCheckState());
        Assert.Equal(4, main.Tiles.Count);
    }

    [Fact]
    public void GroupClick_UsesPreviousDomainState()
    {
        using var main = NewMain();
        main.ApplyServerInventory(new[]
        {
            new ComputerRecord(A, "Alpha", ComputerStatus.Online, null, "lab"),
            new ComputerRecord(B, "Bravo", ComputerStatus.Online, null, "lab"),
            new ComputerRecord(C, "Charlie", ComputerStatus.Online),
        });

        var lab = main.Groups.Single(g => g.Id == "lab").MemberIds;

        // Checked -> exclude members.
        main.ToggleGroupIncludedFromClick(lab);
        Assert.Equal(InclusionCheckState.Unchecked, main.GetGroupCheckState(lab));
        Assert.Equal(new[] { C }, main.Tiles.Select(t => t.Id).ToArray());

        // Unchecked -> include members.
        main.ToggleGroupIncludedFromClick(lab);
        Assert.Equal(InclusionCheckState.Checked, main.GetGroupCheckState(lab));
        Assert.Equal(3, main.Tiles.Count);
    }

    [Fact]
    public void SetAllIncluded_NoOpWhenAlreadyInTargetState()
    {
        using var main = NewMain();
        ApplySample(main);

        main.SetAllIncluded(true);
        Assert.True(main.Overview.Inclusion.IsAllMode);
        // Second call is a no-op and must not churn the tile collection.
        var tiles = main.Tiles.ToArray();
        main.SetAllIncluded(true);
        Assert.Equal(tiles.Length, main.Tiles.Count);
        for (var i = 0; i < tiles.Length; i++)
        {
            Assert.Same(tiles[i], main.Tiles[i]);
        }

        main.SetAllIncluded(false);
        main.SetAllIncluded(false);
        Assert.Empty(main.Tiles);
        Assert.Equal(4, main.AllAuthorizedTiles.Count);
    }

    [Fact]
    public void PreviewSize_LabelsAndSixteenNineHeight()
    {
        Assert.Equal("Compact", PreviewSize.Compact192.Label());
        Assert.Equal("Standard", PreviewSize.Standard256.Label());
        Assert.Equal("Large", PreviewSize.Large320.Label());
        Assert.Equal("Extra Large", PreviewSize.ExtraLarge448.Label());
        Assert.Equal(PreviewSize.Large320, PreviewSizeExtensions.Default);

        Assert.Equal(108, PreviewSize.Compact192.LogicalHeight());
        Assert.Equal(144, PreviewSize.Standard256.LogicalHeight());
        Assert.Equal(180, PreviewSize.Large320.LogicalHeight());
        Assert.Equal(252, PreviewSize.ExtraLarge448.LogicalHeight());

        using var main = NewMain();
        ApplySample(main);
        main.PreviewSize = PreviewSize.Large320;
        Assert.Equal(320, main.Tiles[0].PreviewExtent);
        Assert.Equal(180, main.Tiles[0].PreviewHeight);
    }

    [Fact]
    public void ViewerRegistry_ReopenFocusesExisting_AndStaleCloseKeepsReplacement()
    {
        using var main = NewMain();
        ApplySample(main);

        var first = main.OpenViewScreen(A);
        var again = main.OpenViewScreen(A);
        Assert.Equal(first.Handle, again.Handle);

        // Two independent computers stay independently open.
        var other = main.OpenViewScreen(B);
        Assert.NotEqual(first.Handle, other.Handle);

        // Stale close of a replaced handle cannot remove the replacement.
        Assert.True(main.CloseViewScreen(first.Handle));
        Assert.False(main.Viewers.IsLive(first.Handle));
        var replacement = main.OpenViewScreen(A);
        Assert.NotEqual(first.Handle, replacement.Handle);
        Assert.False(main.CloseViewScreen(first.Handle));
        Assert.True(main.Viewers.IsLive(replacement.Handle));
        Assert.True(main.Viewers.IsLive(other.Handle));
    }

    [Fact]
    public void ViewerRegistry_SessionLossClosesInvalidatedViewers()
    {
        using var main = NewMain();
        ApplySample(main);

        var a = main.OpenViewScreen(A);
        var b = main.OpenViewScreen(B);
        Assert.True(main.Viewers.IsLive(a.Handle));
        Assert.True(main.Viewers.IsLive(b.Handle));

        main.ClearSessionScopedInventory();

        Assert.False(main.Viewers.IsLive(a.Handle));
        Assert.False(main.Viewers.IsLive(b.Handle));
        Assert.Empty(main.Viewers.OpenViewers);
        Assert.Empty(main.Tiles);
    }
    [Fact]
    public void RevocationClosesOnlyAffectedViewerAndFencesLateClose()
    {
        using var main = NewMain();
        ApplySample(main);
        var first = main.OpenViewScreen(A);
        var other = main.OpenViewScreen(B);
        var changed = 0;
        main.Viewers.Changed += (_, _) => changed++;
        main.ApplyServerInventory(new[] { new ComputerRecord(B, "Bravo", ComputerStatus.Online) });
        Assert.False(main.Viewers.IsLive(first.Handle));
        Assert.True(main.Viewers.IsLive(other.Handle));
        Assert.True(changed > 0);
        Assert.Throws<InvalidOperationException>(() => main.OpenViewScreen(A));
        ApplySample(main);
        var replacement = main.OpenViewScreen(A);
        Assert.False(main.CloseViewScreen(first.Handle));
        Assert.True(main.Viewers.IsLive(replacement.Handle));
    }

    [Fact]
    public void RefreshKeepsSelectionWhileFilteringClearsIt()
    {
        using var main = NewMain();
        ApplySample(main);
        main.SelectTile(A, additive: false);
        var updating = false;
        main.TilesUpdating += (_, _) => updating = true;
        main.Tiles.CollectionChanged += (_, _) => Assert.True(updating);
        main.TilesUpdated += (_, _) => updating = false;
        ApplySample(main);
        Assert.True(main.Overview.Selection.IsSelected(A));
        main.OnSearchChanged("Bravo");
        Assert.Empty(main.Overview.Selection.SelectedIds);
        Assert.False(updating);
    }

}
