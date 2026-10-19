using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Helicoid.Domain.Client;
using Helicoid.Domain.Engine;
using Helicoid.Domain.Fixtures;
using Helicoid.Domain.Model;
using Helicoid.Domain.Overview;
using Helicoid.Domain.Setup;

namespace Helicoid.Manager.ViewModels;

/// <summary>
/// Manager application state. Connection and inventory come from
/// <see cref="ConnectionViewModel"/>; overview demand stays on
/// <see cref="OverviewState"/>. Inclusion, displayed IDs, selection, action
/// snapshots, and admitted streams remain separate objects.
/// </summary>
public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly Dictionary<ComputerId, ComputerTile> _tilesById = new();
    private bool _isGridView = true;
    private PreviewSize _previewSize = PreviewSizeExtensions.Default;
    private string _scopeLine = string.Empty;
    private bool _disposed;
    private int _inventorySessionGeneration;
    private int _inventoryLoadEpoch;
    private ComputerId? _selectionAnchor;
    private bool _isComputersPanelExpanded;
    private bool _isInventoryLoading;
    private string? _inventoryLoadError;

    public bool IsInventoryLoading => _isInventoryLoading;
    public string? InventoryLoadError => _inventoryLoadError;
    public event EventHandler? TilesUpdating;
    public event EventHandler? TilesUpdated;

    /// <summary>
    /// Create the manager shell. <paramref name="deviceKeySignIn"/> is optional
    /// caller-supplied v2 sign-in state; this type never builds trust or
    /// enrollment. Session loss clears session-scoped inventory and selection.
    /// </summary>
    public MainViewModel(
        DevelopmentLaunchOptions launchOptions,
        V2SignInCoordinator? deviceKeySignIn = null)
    {
        ArgumentNullException.ThrowIfNull(launchOptions);
        LaunchOptions = launchOptions;
        Client = launchOptions.CreateClient();
        Connection = new ConnectionViewModel(launchOptions, Client, deviceKeySignIn);
        Connection.SessionLost += OnConnectionSessionLost;
        Connection.SessionIdentityChanged += OnConnectionSessionIdentityChanged;
        Connection.PropertyChanged += OnConnectionPropertyChanged;
        Fixtures = new DevelopmentFixtureMode();
        if (launchOptions.DevelopmentFixturesEnabled)
        {
            Fixtures.Enable();
        }

        Overview = new OverviewState();
        EngineStatus = RemoteEngineStatus.UnavailableNoBridge();
        Wizard = new SetupWizard();
        RefreshInventory();
    }

    public DevelopmentLaunchOptions LaunchOptions { get; }

    public IHsServerClient Client { get; }

    public ConnectionViewModel Connection { get; }

    public OverviewState Overview { get; }

    public DevelopmentFixtureMode Fixtures { get; }

    public RemoteEngineStatus EngineStatus { get; }

    public SetupWizard Wizard { get; }

    /// <summary>
    /// Displayed inventory in stable natural-name order. Tile instances are
    /// reused across selection and filter changes so the virtualized
    /// GridView/ListView never rebuilds every object on selection.
    /// </summary>
    public ObservableCollection<ComputerTile> Tiles { get; } = new();

    /// <summary>
    /// Full authorized inventory for the Computers inclusion panel. Stable and
    /// distinct from <see cref="Tiles"/>: filtering or unchecking a computer
    /// never removes it from this collection, so it can be re-included.
    /// </summary>
    public ObservableCollection<ComputerTile> AllAuthorizedTiles { get; } = new();

    /// <summary>Session-only layout. Never persisted under a global key.</summary>
    public bool IsGridView
    {
        get => _isGridView;
        set
        {
            if (_isGridView == value)
            {
                return;
            }

            _isGridView = value;
            OnPropertyChanged();
        }
    }

    /// <summary>
    /// Session-only preview density (Compact192/Standard256/Large320/ExtraLarge448).
    /// Changing this must not reset selection, filters, or inclusion.
    /// </summary>
    public PreviewSize PreviewSize
    {
        get => _previewSize;
        set
        {
            if (_previewSize == value)
            {
                return;
            }

            _previewSize = value;
            var extent = value.LogicalPixels();
            foreach (var tile in _tilesById.Values)
            {
                tile.PreviewExtent = extent;
            }

            OnPropertyChanged();
            OnPropertyChanged(nameof(PreviewSizeLabel));
            OnPropertyChanged(nameof(PreviewSizePixels));
        }
    }

    public string PreviewSizeLabel => _previewSize.Label();

    public int PreviewSizePixels => _previewSize.LogicalPixels();

    /// <summary>Optional flat groups derived from inventory. Empty when unused.</summary>
    public ObservableCollection<InclusionGroupRow> Groups { get; } = new();

    /// <summary>
    /// Portable open-viewer registry keyed by computer and session context.
    /// WinUI hosts hold the actual windows; this seam owns identity/lifetime.
    /// </summary>
    public ViewerRegistry Viewers { get; } = new();

    /// <summary>Computers panel expansion. Optional UI; default follows groups.</summary>
    public bool IsComputersPanelExpanded
    {
        get => _isComputersPanelExpanded;
        set { _isComputersPanelExpanded = value; OnPropertyChanged(); }
    }

    public string ScopeLine
    {
        get => _scopeLine;
        private set { _scopeLine = value; OnPropertyChanged(); }
    }

    /// <summary>Plain status for the engine. Keep technical IDs out of UI copy.</summary>
    public string EngineStatusText =>
        "Live previews and remote control are not available yet.";

    /// <summary>Honest tile preview copy when the remote engine is missing.</summary>
    public string ScreenUnavailableTitle => "Screen Unavailable";

    public string ScreenUnavailableDetail => EngineStatus.Reason;

    /// <summary>True while overview session demand is paused.</summary>
    public bool IsMonitoringPaused => Overview.IsMonitoringPaused;

    /// <summary>Why the inventory area is empty, for distinct empty states.</summary>
    public InventoryEmptyKind EmptyKind => Overview.EmptyKind;

    public event PropertyChangedEventHandler? PropertyChanged;

    public void SetFixtureMode(bool enabled)
    {
        if (enabled)
        {
            Fixtures.Enable();
        }
        else
        {
            Fixtures.Disable();
        }

        RefreshInventory();
    }

    /// <summary>
    /// Load fixture or local inventory into the overview. Fixture sample data
    /// stays separate from server inventory.
    /// </summary>
    public void RefreshInventory()
    {
        var inventory = Fixtures.BuildInventoryOrEmpty();
        ApplyInventoryCore(inventory);
    }

    /// <summary>
    /// Apply server inventory for the current session generation. Stale loads
    /// from a previous identity are rejected by the load epoch fence.
    /// </summary>
    public void ApplyServerInventory(IReadOnlyList<ComputerRecord> inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        ApplyInventoryCore(inventory);
        _inventorySessionGeneration = Connection.DeviceKeySignIn?.InstalledSessionGeneration ?? 0;
    }

    /// <summary>
    /// Begin a fenced inventory load. The returned epoch must be passed to
    /// <see cref="TryCompleteInventoryLoad"/> so a late response cannot leak
    /// inventory from a cancelled or replaced session.
    /// </summary>
    public int BeginInventoryLoad()
    {
        return ++_inventoryLoadEpoch;
    }

    /// <summary>
    /// Complete a fenced inventory load. Returns false and applies nothing when
    /// the load was superseded or cancelled by a newer load or session clear.
    /// </summary>
    public bool TryCompleteInventoryLoad(int loadEpoch, IReadOnlyList<ComputerRecord> inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        if (loadEpoch != _inventoryLoadEpoch)
        {
            return false;
        }

        ApplyServerInventory(inventory);
        return true;
    }

    /// <summary>
    /// Refresh inventory from the server under the load-epoch fence. Safe to
    /// call after sign-in and on page entry. A secondary explicit Refresh uses
    /// the same fenced path. A failed fetch never clears existing inventory.
    /// </summary>
    public async Task RefreshInventoryFromServerAsync(CancellationToken cancellationToken)
    {
        if (Connection.State != ConnectionUiState.SignedIn)
        {
            return;
        }

        var epoch = BeginInventoryLoad();
        IReadOnlyList<ComputerRecord>? loaded = null;
        _isInventoryLoading = true;
        _inventoryLoadError = null;
        OnPropertyChanged(nameof(IsInventoryLoading));
        OnPropertyChanged(nameof(InventoryLoadError));
        try
        {
            await Connection.RefreshInventoryAsync(
                inventory => loaded = inventory,
                cancellationToken).ConfigureAwait(true);
            if (cancellationToken.IsCancellationRequested || epoch != _inventoryLoadEpoch) return;
            if (loaded is null)
            {
                _inventoryLoadError = "Couldn’t refresh computers. Try again.";
                return;
            }
            TryCompleteInventoryLoad(epoch, loaded);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception)
        {
            if (epoch == _inventoryLoadEpoch) _inventoryLoadError = "Couldn’t refresh computers. Try again.";
        }
        finally
        {
            if (epoch == _inventoryLoadEpoch)
            {
                _isInventoryLoading = false;
                OnPropertyChanged(nameof(IsInventoryLoading));
                OnPropertyChanged(nameof(InventoryLoadError));
            }
        }
    }

    public void OnSearchChanged(string? query)
    {
        Overview.SetSearch(query);
        SyncTilesFromOverview();
    }

    public void OnStatusFilterChanged(StatusFilter filter)
    {
        Overview.SetStatusFilter(filter);
        SyncTilesFromOverview();
    }

    /// <summary>Clear search and status filters only.</summary>
    public void ClearFilters()
    {
        Overview.ClearFilters();
        SyncTilesFromOverview();
    }

    /// <summary>Open the Computers inclusion panel (Choose Computers).</summary>
    public void ChooseComputers()
    {
        IsComputersPanelExpanded = true;
    }

    public void ToggleInclusionAll() => ToggleAllIncludedFromClick();

    /// <summary>
    /// All Computers click uses the previous domain state, not the native
    /// post-click checkbox value: Checked clears to empty; Mixed/Unchecked
    /// includes all. Always syncs the displayed collection.
    /// </summary>
    public void ToggleAllIncludedFromClick()
    {
        var previous = GetAllComputersCheckState();
        if (previous == InclusionCheckState.Checked)
        {
            Overview.Inclusion.ClearToEmptyExplicit();
        }
        else
        {
            Overview.Inclusion.CheckAll();
        }

        Overview.SetInclusion(Overview.Inclusion);
        SyncTilesFromOverview();
    }

    /// <summary>Set All Computers inclusion explicitly and sync tiles.</summary>
    public void SetAllIncluded(bool included)
    {
        if (included)
        {
            if (GetAllComputersCheckState() == InclusionCheckState.Checked)
            {
                return;
            }

            Overview.Inclusion.CheckAll();
        }
        else
        {
            if (GetAllComputersCheckState() == InclusionCheckState.Unchecked)
            {
                return;
            }

            Overview.Inclusion.ClearToEmptyExplicit();
        }

        Overview.SetInclusion(Overview.Inclusion);
        SyncTilesFromOverview();
    }

    /// <summary>
    /// Group click uses the previous domain state: Checked excludes members;
    /// Mixed/Unchecked includes them. Always syncs the displayed collection.
    /// </summary>
    public void ToggleGroupIncludedFromClick(IReadOnlyList<ComputerId> memberIds)
    {
        ArgumentNullException.ThrowIfNull(memberIds);
        if (memberIds.Count == 0)
        {
            return;
        }

        var previous = Overview.Inclusion.GetGroupCheckState(memberIds);
        SetGroupIncluded(memberIds, included: previous != InclusionCheckState.Checked);
    }

    /// <summary>
    /// Set one computer's overview inclusion. Separate from tile selection and
    /// from authorization. No-op when the checkbox state already matches.
    /// </summary>
    public void SetComputerIncluded(ComputerId id, bool included)
    {
        var authorizedIds = _tilesById.Keys.ToList();
        if (authorizedIds.Count == 0)
        {
            authorizedIds = Overview.DisplayedIds.ToList();
        }

        if (Overview.Inclusion.Contains(id) == included)
        {
            return;
        }

        Overview.Inclusion.SetIncluded(id, included, authorizedIds);
        Overview.SetInclusion(Overview.Inclusion);
        SyncTilesFromOverview();
    }

    /// <summary>Tri-state for the All Computers checkbox.</summary>
    public InclusionCheckState GetAllComputersCheckState() =>
        Overview.Inclusion.GetAllCheckState(_tilesById.Keys.ToList());

    /// <summary>Tri-state for one group's member IDs.</summary>
    public InclusionCheckState GetGroupCheckState(IReadOnlyList<ComputerId> memberIds) =>
        Overview.Inclusion.GetGroupCheckState(memberIds);

    /// <summary>Set every member of a group included or excluded.</summary>
    public void SetGroupIncluded(IReadOnlyList<ComputerId> memberIds, bool included)
    {
        ArgumentNullException.ThrowIfNull(memberIds);
        if (memberIds.Count == 0)
        {
            return;
        }

        Overview.Inclusion.SetGroupIncluded(memberIds, included, _tilesById.Keys.ToList());
        Overview.SetInclusion(Overview.Inclusion);
        SyncTilesFromOverview();
    }

    /// <summary>
    /// Select one tile. <paramref name="additive"/> toggles (Ctrl/Command);
    /// <paramref name="range"/> extends from the anchor along displayed order
    /// (Shift). Right-click on an unselected tile replaces the selection.
    /// </summary>
    public void SelectTile(ComputerId id, bool additive, bool range = false)
    {
        if (range && _selectionAnchor is { } anchor)
        {
            Overview.Selection.ExtendAlong(anchor, id, Overview.DisplayedIds);
        }
        else if (additive)
        {
            Overview.ToggleSelection(id);
            _selectionAnchor = id;
        }
        else
        {
            Overview.SelectOnly(id);
            _selectionAnchor = id;
        }

        SyncSelectionFlags();
    }

    public void ClearSelection()
    {
        Overview.ClearSelection();
        _selectionAnchor = null;
        SyncSelectionFlags();
    }

    /// <summary>
    /// Map native GridView/ListView Extended selection onto the domain model
    /// without rebuilding tile instances.
    /// </summary>
    public void ApplyNativeSelection(IReadOnlyList<ComputerId> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        Overview.ClearSelection();
        foreach (var id in ids)
        {
            if (Overview.DisplayedIds.Contains(id))
            {
                Overview.Selection.Select(id);
            }
        }

        _selectionAnchor = ids.Count > 0 ? ids[^1] : null;
        SyncSelectionFlags();
    }

    /// <summary>Pause overview demand and clear admitted streams.</summary>
    public void PauseMonitoring()
    {
        Overview.PauseMonitoring();
        OnPropertyChanged(nameof(IsMonitoringPaused));
    }

    /// <summary>Resume overview demand. No streams are fabricated.</summary>
    public void ResumeMonitoring()
    {
        Overview.ResumeMonitoring();
        OnPropertyChanged(nameof(IsMonitoringPaused));
    }

    /// <summary>Toggle Pause/Resume session demand state.</summary>
    public void ToggleMonitoringPause()
    {
        if (Overview.IsMonitoringPaused)
        {
            ResumeMonitoring();
        }
        else
        {
            PauseMonitoring();
        }
    }

    public ActionSnapshot? TryOpenAction(string actionName)
    {
        try
        {
            return Overview.OpenAction(actionName);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _inventoryLoadEpoch++;
        // Independent view-only windows are not disposed with the main window.
        // Session loss closes invalidated viewers; host close leaves others open.
        Connection.SessionLost -= OnConnectionSessionLost;
        Connection.SessionIdentityChanged -= OnConnectionSessionIdentityChanged;
        Connection.PropertyChanged -= OnConnectionPropertyChanged;
        Connection.Dispose();
    }

    /// <summary>Open or focus a view-only viewer for this computer.</summary>
    public ViewerRegistry.ViewerToken OpenViewScreen(ComputerId id)
    {
        if (!_tilesById.ContainsKey(id)) throw new InvalidOperationException("Computer is no longer authorized.");
        var session = Connection.DeviceKeySignIn?.InstalledSessionGeneration ?? 0;
        return Viewers.OpenOrFocus(id, session);
    }

    /// <summary>Close one viewer by handle. Stale handles are ignored.</summary>
    public bool CloseViewScreen(int handle) => Viewers.Close(handle);

    /// <summary>
    /// Session-scoped inventory and selection cannot outlive the session.
    /// Reconnect never restores control (still unavailable). Device-key loss is
    /// generation-fenced via SessionIdentityChanged; this generic path is the
    /// legacy/no-v2 sign-out cleanup only and must not erase a replacement.
    /// </summary>
    private void OnConnectionSessionLost(object? sender, EventArgs e)
    {
        if (Connection.DeviceKeySignIn is not null)
        {
            // Identity transitions own device-key cleanup.
            return;
        }

        ClearSessionScopedInventory();
    }

    /// <summary>
    /// Generation-fenced identity transition. Clears inventory bound to the
    /// old identity even when no transient signed-out Phase was observed;
    /// a stale reset never erases inventory already loaded for a newer session.
    /// Selection is session-scoped and is dropped on any identity change.
    /// </summary>
    private void OnConnectionSessionIdentityChanged(object? sender, SessionIdentityChangedEventArgs e)
    {
        if (e.NewGeneration == e.OldGeneration)
        {
            return;
        }

        Viewers.CloseSession(e.OldGeneration);
        if (_inventorySessionGeneration != 0 && _inventorySessionGeneration == e.OldGeneration)
        {
            ClearSessionScopedInventory();
            return;
        }

        if (_inventorySessionGeneration == 0 && e.NewGeneration == 0 && e.OldGeneration != 0)
        {
            ClearSessionScopedInventory();
            return;
        }

        // Inventory already belongs to a newer live identity: keep it.
        // Selection still referenced the departed identity and must not leak.
        if (e.OldGeneration != 0 || e.NewGeneration != 0)
        {
            ClearSelection();
        }
    }

    private void OnConnectionPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ConnectionViewModel.State)
            && Connection.State == ConnectionUiState.SignedIn)
        {
            // Automatic inventory after actual sign-in. Generation fenced.
            // Observe the task so a failed refresh is never unhandled and never
            // clears existing inventory (RefreshInventoryFromServerAsync keeps
            // current rows when the fetch fails).
            _autoRefreshTask = ObserveAutoRefreshAsync();
        }
    }

    private Task? _autoRefreshTask;

    private async Task ObserveAutoRefreshAsync()
    {
        try
        {
            await RefreshInventoryFromServerAsync(CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception)
        {
            // Secondary refresh failure: keep current inventory on screen.
            // ConnectionViewModel already classified transport failures.
        }
    }

    /// <summary>
    /// Drop session-scoped inventory and selection and fence in-flight loads.
    /// Called on session loss and identity change cleanup.
    /// </summary>
    public void ClearSessionScopedInventory()
    {
        var session = _inventorySessionGeneration;
        _inventoryLoadEpoch++;
        _inventorySessionGeneration = 0;
        _selectionAnchor = null;
        _isInventoryLoading = false;
        _inventoryLoadError = null;
        OnPropertyChanged(nameof(IsInventoryLoading));
        OnPropertyChanged(nameof(InventoryLoadError));
        ApplyInventoryCore(Array.Empty<ComputerRecord>());
        Overview.ClearSelection();
        SyncSelectionFlags();
        Viewers.CloseSession(session);
        InventoryCleared?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Raised when session-scoped inventory is cleared so UI-owned viewers
    /// and lists can close/drop invalidated state.
    /// </summary>
    public event EventHandler? InventoryCleared;

    private void ApplyInventoryCore(IReadOnlyList<ComputerRecord> inventory)
    {
        var authorized = inventory.Select(c => c.Id).ToList();
        Viewers.RetainAuthorized(authorized.ToHashSet());
        Overview.UpdateInventory(inventory, authorized);
        RebuildTileInstances(inventory);
        SyncTilesFromOverview();
    }

    /// <summary>
    /// Create or reuse one <see cref="ComputerTile"/> per inventory row.
    /// Selection never recreates instances. <see cref="AllAuthorizedTiles"/>
    /// always tracks the full authorized inventory in stable order.
    /// </summary>
    private void RebuildTileInstances(IReadOnlyList<ComputerRecord> inventory)
    {
        var extent = _previewSize.LogicalPixels();
        var seen = new HashSet<ComputerId>();
        foreach (var record in inventory)
        {
            seen.Add(record.Id);
            if (_tilesById.TryGetValue(record.Id, out var existing))
            {
                existing.UpdateRecord(record);
            }
            else
            {
                _tilesById[record.Id] = new ComputerTile(record, extent);
            }
        }

        foreach (var stale in _tilesById.Keys.Where(id => !seen.Contains(id)).ToList())
        {
            _tilesById.Remove(stale);
        }

        SyncAllAuthorizedTiles(inventory);
        RebuildGroups(inventory);
    }

    /// <summary>
    /// Stable full-inventory list for the inclusion panel. Distinct from the
    /// displayed <see cref="Tiles"/> collection; never filtered.
    /// </summary>
    private void SyncAllAuthorizedTiles(IReadOnlyList<ComputerRecord> inventory)
    {
        var ordered = ComputerOrdering.OrderForDisplay(inventory).ToList();
        var target = new List<ComputerTile>(ordered.Count);
        foreach (var record in ordered)
        {
            if (_tilesById.TryGetValue(record.Id, out var tile))
            {
                target.Add(tile);
            }
        }

        AllAuthorizedTiles.Clear();
        foreach (var tile in target)
        {
            AllAuthorizedTiles.Add(tile);
        }
    }

    private void RebuildGroups(IReadOnlyList<ComputerRecord> inventory)
    {
        var rows = inventory
            .Where(r => !string.IsNullOrEmpty(r.GroupId))
            .GroupBy(r => r.GroupId!)
            .Select(g => new InclusionGroupRow(
                g.Key,
                g.Key,
                g.Select(r => r.Id).ToList()))
            .OrderBy(g => g.Name, ComputerOrdering.NaturalNameComparer.Instance)
            .ThenBy(g => g.Id, StringComparer.Ordinal)
            .ToList();

        Groups.Clear();
        foreach (var row in rows)
        {
            Groups.Add(row);
        }
    }

    /// <summary>
    /// Sync the bound <see cref="Tiles"/> collection to current displayed order
    /// without rebuilding tile objects. Selection changes only touch flags.
    /// </summary>
    private void SyncTilesFromOverview()
    {
        TilesUpdating?.Invoke(this, EventArgs.Empty);
        try
        {
            SyncDisplayedTiles();
        }
        finally
        {
            TilesUpdated?.Invoke(this, EventArgs.Empty);
        }
    }

    private void SyncDisplayedTiles()
    {
        var displayed = Overview.DisplayedIds;
        var target = new List<ComputerTile>(displayed.Count);
        foreach (var id in displayed)
        {
            if (_tilesById.TryGetValue(id, out var tile))
            {
                target.Add(tile);
            }
        }

        // Reorder/replace collection contents while reusing instances.
        for (var i = 0; i < target.Count; i++)
        {
            if (i < Tiles.Count)
            {
                if (!ReferenceEquals(Tiles[i], target[i]))
                {
                    var existingIndex = Tiles.IndexOf(target[i]);
                    if (existingIndex >= 0)
                    {
                        Tiles.Move(existingIndex, i);
                    }
                    else
                    {
                        Tiles.Insert(i, target[i]);
                    }
                }
            }
            else
            {
                Tiles.Add(target[i]);
            }
        }

        while (Tiles.Count > target.Count)
        {
            Tiles.RemoveAt(Tiles.Count - 1);
        }

        SyncSelectionFlags();
    }

    private void SyncSelectionFlags()
    {
        foreach (var tile in _tilesById.Values)
        {
            tile.IsSelected = Overview.Selection.IsSelected(tile.Id);
            tile.IsIncludedInOverview = Overview.Inclusion.Contains(tile.Id);
        }

        foreach (var group in Groups)
        {
            group.CheckState = Overview.Inclusion.GetGroupCheckState(group.MemberIds);
        }

        UpdateScopeLine();
    }

    private void UpdateScopeLine()
    {
        if (Overview.Selection.Count > 0)
        {
            ScopeLine = Overview.Selection.Count == 1 ? "1 Computer Selected" : $"{Overview.Selection.Count} Computers Selected";
        }
        else if (Overview.DisplayedIds.Count == 0)
        {
            ScopeLine = Overview.EmptyKind switch
            {
                InventoryEmptyKind.NoInclusion => "No Computers Included",
                InventoryEmptyKind.NoMatches => "No Computers Match",
                _ => "No Computers Displayed",
            };
        }
        else
        {
            ScopeLine = $"All {Overview.DisplayedIds.Count} Displayed Computers";
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class ComputerTile : INotifyPropertyChanged
{
    private bool _isSelected;
    private bool _isIncludedInOverview;
    private int _previewExtent;

    public ComputerTile(ComputerRecord record, int previewExtent)
    {
        Record = record;
        _previewExtent = previewExtent;
    }

    public ComputerRecord Record { get; private set; }

    public ComputerId Id => Record.Id;

    public string Name => Record.Name;

    public string? TrustedUserName => Record.TrustedUserName;

    public string? GroupId => Record.GroupId;

    public ComputerStatus Status => Record.Status;

    public bool HasTrustedUser => !string.IsNullOrEmpty(Record.TrustedUserName);

    public bool HasException => ExceptionText is not null;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value)
            {
                return;
            }

            _isSelected = value;
            OnPropertyChanged();
        }
    }

    /// <summary>Overview inclusion demand. Separate from selection.</summary>
    public bool IsIncludedInOverview
    {
        get => _isIncludedInOverview;
        set
        {
            if (_isIncludedInOverview == value)
            {
                return;
            }

            _isIncludedInOverview = value;
            OnPropertyChanged();
        }
    }

    /// <summary>Logical preview width for the current session density.</summary>
    public int PreviewExtent
    {
        get => _previewExtent;
        set
        {
            if (_previewExtent == value)
            {
                return;
            }

            _previewExtent = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(PreviewHeight));
        }
    }

    /// <summary>Preview well height at 16:9 until real frame metadata exists.</summary>
    public int PreviewHeight =>
        (int)Math.Round(_previewExtent / PreviewSizeExtensions.PreviewAspectRatio);

    /// <summary>
    /// Quiet readiness copy for the preview well. No green Online badge;
    /// missing engine states Screen Unavailable rather than a live claim.
    /// </summary>
    public string PreviewTitle => "Screen Unavailable";

    public string PreviewDetail => Status switch
    {
        ComputerStatus.Online => "Not live. Remote engine is not available in this build.",
        ComputerStatus.Connecting => "Connecting. Remote engine is not available in this build.",
        ComputerStatus.Offline => "Offline. Remote engine is not available in this build.",
        ComputerStatus.NeedsAttention => "Needs attention. Remote engine is not available in this build.",
        ComputerStatus.PendingApproval => "Pending approval. Remote engine is not available in this build.",
        ComputerStatus.Failed => "Connection failed. Remote engine is not available in this build.",
        ComputerStatus.Unavailable => "Unavailable. Remote engine is not available in this build.",
        _ => "Remote engine is not available in this build.",
    };

    /// <summary>Exception-only secondary line. Quiet when nothing is wrong.</summary>
    public string? ExceptionText => Status switch
    {
        ComputerStatus.NeedsAttention => "Needs attention",
        ComputerStatus.Failed => "Connection failed",
        ComputerStatus.PendingApproval => "Pending approval",
        ComputerStatus.Unavailable => "Unavailable",
        _ => null,
    };

    /// <summary>Update inventory data without replacing the tile instance.</summary>
    public void UpdateRecord(ComputerRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (Record.Id != record.Id)
        {
            throw new ArgumentException("Tile identity cannot change.", nameof(record));
        }

        var nameChanged = Record.Name != record.Name;
        var userChanged = Record.TrustedUserName != record.TrustedUserName;
        var statusChanged = Record.Status != record.Status;
        var groupChanged = Record.GroupId != record.GroupId;
        Record = record;
        if (nameChanged)
        {
            OnPropertyChanged(nameof(Name));
        }

        if (userChanged)
        {
            OnPropertyChanged(nameof(TrustedUserName));
            OnPropertyChanged(nameof(HasTrustedUser));
        }

        if (statusChanged)
        {
            OnPropertyChanged(nameof(Status));
            OnPropertyChanged(nameof(PreviewDetail));
            OnPropertyChanged(nameof(ExceptionText));
            OnPropertyChanged(nameof(HasException));
        }

        if (groupChanged)
        {
            OnPropertyChanged(nameof(GroupId));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>Optional flat group row for the Computers panel inclusion list.</summary>
public sealed class InclusionGroupRow : INotifyPropertyChanged
{
    private InclusionCheckState _checkState;

    public InclusionGroupRow(string id, string name, IReadOnlyList<ComputerId> memberIds)
    {
        Id = id;
        Name = name;
        MemberIds = memberIds;
    }

    public string Id { get; }

    public string Name { get; }

    public IReadOnlyList<ComputerId> MemberIds { get; }

    public InclusionCheckState CheckState
    {
        get => _checkState;
        set
        {
            if (_checkState == value)
            {
                return;
            }

            _checkState = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsChecked));
        }
    }

    /// <summary>Native tri-state checkbox value for this group.</summary>
    public bool? IsChecked => _checkState switch
    {
        InclusionCheckState.Checked => true,
        InclusionCheckState.Unchecked => false,
        _ => null,
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
