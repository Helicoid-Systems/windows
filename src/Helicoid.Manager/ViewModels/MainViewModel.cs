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
public sealed class MainViewModel : INotifyPropertyChanged
{
    private bool _isGridView = true;
    private string _scopeLine = string.Empty;

    public MainViewModel(DevelopmentLaunchOptions launchOptions)
    {
        ArgumentNullException.ThrowIfNull(launchOptions);
        LaunchOptions = launchOptions;
        Client = launchOptions.CreateClient();
        Connection = new ConnectionViewModel(launchOptions, Client);
        Fixtures = new DevelopmentFixtureMode();
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

    public ObservableCollection<ComputerTile> Tiles { get; } = new();

    public bool IsGridView
    {
        get => _isGridView;
        set { _isGridView = value; OnPropertyChanged(); }
    }

    public string ScopeLine
    {
        get => _scopeLine;
        private set { _scopeLine = value; OnPropertyChanged(); }
    }

    /// <summary>Plain status for the engine. Keep technical IDs out of UI copy.</summary>
    public string EngineStatusText =>
        "Live previews and remote control are not available yet.";

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

    public void RefreshInventory()
    {
        // Fixture sample data stays separate from server inventory.
        var inventory = Fixtures.BuildInventoryOrEmpty();
        var authorized = inventory.Select(c => c.Id).ToList();
        Overview.UpdateInventory(inventory, authorized);
        RebuildTiles(inventory);
        UpdateScopeLine();
    }

    public void ApplyServerInventory(IReadOnlyList<ComputerRecord> inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        var authorized = inventory.Select(c => c.Id).ToList();
        Overview.UpdateInventory(inventory, authorized);
        RebuildTiles(inventory);
        UpdateScopeLine();
    }

    public void OnSearchChanged(string? query)
    {
        Overview.SetSearch(query);
        RefreshTilesFromOverview();
    }

    public void OnStatusFilterChanged(StatusFilter filter)
    {
        Overview.SetStatusFilter(filter);
        RefreshTilesFromOverview();
    }

    public void ToggleInclusionAll()
    {
        if (Overview.Inclusion.IsAllMode)
        {
            Overview.Inclusion.ClearToEmptyExplicit();
        }
        else
        {
            Overview.Inclusion.CheckAll();
        }

        Overview.SetInclusion(Overview.Inclusion);
        RefreshTilesFromOverview();
    }

    public void SelectTile(ComputerId id, bool additive)
    {
        if (additive)
        {
            Overview.ToggleSelection(id);
        }
        else
        {
            Overview.SelectOnly(id);
        }

        RefreshTilesFromOverview();
    }

    public void ClearSelection()
    {
        Overview.ClearSelection();
        RefreshTilesFromOverview();
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

    private void RebuildTiles(IReadOnlyList<ComputerRecord> inventory)
    {
        Tiles.Clear();
        foreach (var record in inventory)
        {
            Tiles.Add(new ComputerTile(record));
        }

        RefreshTilesFromOverview();
    }

    private void RefreshTilesFromOverview()
    {
        var displayed = Overview.DisplayedIds.ToHashSet();
        foreach (var tile in Tiles)
        {
            tile.IsDisplayed = displayed.Contains(tile.Id);
            tile.IsSelected = Overview.Selection.IsSelected(tile.Id);
        }

        UpdateScopeLine();
    }

    private void UpdateScopeLine()
    {
        if (Overview.Selection.Count > 0)
        {
            ScopeLine = $"{Overview.Selection.Count} Computer(s) Selected";
        }
        else if (Overview.DisplayedIds.Count == 0)
        {
            ScopeLine = "No Computers Displayed";
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
    private bool _isDisplayed;
    private bool _isSelected;

    public ComputerTile(ComputerRecord record)
    {
        Record = record;
    }

    public ComputerRecord Record { get; }

    public ComputerId Id => Record.Id;

    public string Name => Record.Name;

    public string? TrustedUserName => Record.TrustedUserName;

    public ComputerStatus Status => Record.Status;

    public bool IsDisplayed
    {
        get => _isDisplayed;
        set { _isDisplayed = value; OnPropertyChanged(); }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set { _isSelected = value; OnPropertyChanged(); }
    }

    /// <summary>Honest preview readiness. No fake frames.</summary>
    public string PreviewPlaceholder => Status switch
    {
        ComputerStatus.Online => "Waiting for connection",
        ComputerStatus.Connecting => "Connecting",
        ComputerStatus.Offline => "Offline",
        ComputerStatus.NeedsAttention => "Needs attention",
        ComputerStatus.PendingApproval => "Pending approval",
        ComputerStatus.Failed => "Connection failed",
        ComputerStatus.Unavailable => "Unavailable",
        _ => "Unknown",
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
