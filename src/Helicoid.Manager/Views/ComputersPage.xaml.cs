using System.ComponentModel;
using Helicoid.Domain.Model;
using Helicoid.Domain.Overview;
using Helicoid.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace Helicoid.Manager.Views;

public sealed partial class ComputersPage : Page
{
    private bool _syncingChecks;
    private bool _syncingSelection;
    private bool _syncingTiles;
    private CancellationTokenSource? _pageLoadCts;

    public MainViewModel ViewModel { get; private set; } = null!;

    public ComputersPage()
    {
        InitializeComponent();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is not MainViewModel vm)
        {
            return;
        }

        ViewModel = vm;
        DataContext = vm;
        InventoryHost.ItemsSource = vm.Tiles;
        GroupCheckList.ItemsSource = vm.Groups;
        // Inclusion panel always shows the full authorized inventory, never the
        // filtered preview set, so an excluded computer can be re-included.
        ComputerCheckList.ItemsSource = vm.AllAuthorizedTiles;
        ApplyLayoutChrome();
        RefreshScope();
        SyncInclusionChecks();
        PanelToggle.IsChecked = vm.IsComputersPanelExpanded;

        vm.PropertyChanged += OnViewModelPropertyChanged;
        vm.TilesUpdating += OnTilesUpdating;
        vm.TilesUpdated += OnTilesUpdated;

        _pageLoadCts?.Cancel();
        _pageLoadCts?.Dispose();
        _pageLoadCts = new CancellationTokenSource();
        if (vm.Connection.State == ConnectionUiState.SignedIn)
        {
            await RunPageInventoryLoadAsync(_pageLoadCts.Token);
        }
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        base.OnNavigatedFrom(e);
        if (ViewModel is not null)
        {
            ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
            ViewModel.TilesUpdating -= OnTilesUpdating;
            ViewModel.TilesUpdated -= OnTilesUpdated;
        }

        _pageLoadCts?.Cancel();
        _pageLoadCts?.Dispose();
        _pageLoadCts = null;
    }

    private async Task RunPageInventoryLoadAsync(CancellationToken cancellationToken)
    {
        if (ViewModel is null)
        {
            return;
        }

        try
        {
            await ViewModel.RefreshInventoryFromServerAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Page left or a newer load superseded this one.
        }
        catch (Exception)
        {
            // Secondary refresh failure: never convert into empty inventory.
        }

        if (!cancellationToken.IsCancellationRequested)
        {
            RefreshScope();
            SyncInclusionChecks();
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(MainViewModel.IsInventoryLoading):
            case nameof(MainViewModel.InventoryLoadError):
            case nameof(MainViewModel.ScopeLine):
            case nameof(MainViewModel.EmptyKind):
            case nameof(MainViewModel.IsMonitoringPaused):
            case nameof(MainViewModel.PreviewSize):
            case nameof(MainViewModel.IsGridView):
            case nameof(MainViewModel.PreviewSizeLabel):
                RefreshScope();
                break;
        }
    }

    private void OnTilesUpdating(object? sender, EventArgs e) => _syncingTiles = true;

    private void OnTilesUpdated(object? sender, EventArgs e)
    {
        SyncNativeSelectionFromViewModel();
        _syncingTiles = false;
        RefreshScope();
        SyncInclusionChecks();
    }

    private void ApplyLayoutChrome()
    {
        if (ViewModel is null)
        {
            return;
        }

        InventoryHost.ItemTemplate = (DataTemplate)Resources[
            ViewModel.IsGridView ? "GridTileTemplate" : "ListRowTemplate"];
        InventoryHost.ItemsPanel = (ItemsPanelTemplate)Resources[
            ViewModel.IsGridView ? "WrapPanel" : "StackPanel"];
    }

    private void RefreshScope()
    {
        if (ViewModel is null)
        {
            return;
        }

        ScopeLine.Text = ViewModel.ScopeLine;
        InventoryStatus.Text = ViewModel.IsInventoryLoading
            ? "Connecting to Server" : ViewModel.InventoryLoadError ?? string.Empty;
        InventoryStatus.Visibility = string.IsNullOrEmpty(InventoryStatus.Text) ? Visibility.Collapsed : Visibility.Visible;
        var empty = ViewModel.Tiles.Count == 0;
        EmptyState.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        if (empty)
        {
            switch (ViewModel.EmptyKind)
            {
                case InventoryEmptyKind.NoInclusion:
                    EmptyStateTitle.Text = "No computers are included";
                    EmptyStateDetail.Text = "Open Choose Computers to include computers in the overview.";
                    break;
                case InventoryEmptyKind.NoMatches:
                    EmptyStateTitle.Text = "No computers match";
                    EmptyStateDetail.Text = "Clear Filters or change the search to see included computers.";
                    break;
                default:
                    EmptyStateTitle.Text = ViewModel.IsInventoryLoading ? "Connecting to Server"
                        : ViewModel.InventoryLoadError is not null ? "Computers Unavailable" : "No Computers";
                    EmptyStateDetail.Text = ViewModel.IsInventoryLoading ? string.Empty
                        : ViewModel.InventoryLoadError ?? "No computers are authorized for this account.";
                    break;
            }
        }

        var paused = ViewModel.IsMonitoringPaused;
        PauseResumeButton.Label = paused ? "Resume Monitoring" : "Pause Monitoring";
        PauseResumeButton.Icon = new FontIcon { Glyph = paused ? "\uE768" : "\uE769" };
    }

    private void SyncInclusionChecks()
    {
        if (ViewModel is null)
        {
            return;
        }

        _syncingChecks = true;
        try
        {
            var state = ViewModel.GetAllComputersCheckState();
            AllComputersCheck.IsChecked = state switch
            {
                InclusionCheckState.Checked => true,
                InclusionCheckState.Unchecked => false,
                _ => null,
            };

            foreach (var group in ViewModel.Groups)
            {
                group.CheckState = ViewModel.GetGroupCheckState(group.MemberIds);
            }
        }
        finally
        {
            _syncingChecks = false;
        }
    }

    private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput && ViewModel is not null)
        {
            // Filter change may clear domain selection; suppress native reinstall.
            _syncingSelection = true;
            try
            {
                ViewModel.OnSearchChanged(sender.Text);
            }
            finally
            {
                _syncingSelection = false;
            }

            SyncNativeSelectionFromViewModel();
            RefreshScope();
            SyncInclusionChecks();
        }
    }

    private void StatusFilterBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        var filter = StatusFilterBox.SelectedIndex switch
        {
            1 => StatusFilter.Online,
            2 => StatusFilter.NeedsAttention,
            _ => StatusFilter.All,
        };

        _syncingSelection = true;
        try
        {
            ViewModel.OnStatusFilterChanged(filter);
        }
        finally
        {
            _syncingSelection = false;
        }

        SyncNativeSelectionFromViewModel();
        RefreshScope();
    }

    private void AllComputersCheck_Click(object sender, RoutedEventArgs e)
    {
        if (_syncingChecks || ViewModel is null)
        {
            return;
        }

        // Route through the VM. Tri-state uses PREVIOUS domain state:
        // Checked -> empty; Mixed/Unchecked -> all. Never the post-click value.
        _syncingSelection = true;
        try
        {
            ViewModel.ToggleAllIncludedFromClick();
        }
        finally
        {
            _syncingSelection = false;
        }

        SyncNativeSelectionFromViewModel();
        RefreshScope();
        SyncInclusionChecks();
    }

    private void GroupCheck_Click(object sender, RoutedEventArgs e)
    {
        if (_syncingChecks || ViewModel is null || sender is not CheckBox box)
        {
            return;
        }

        if (box.Tag is not InclusionGroupRow row)
        {
            return;
        }

        _syncingSelection = true;
        try
        {
            // Previous domain state: Checked -> exclude; Mixed/Unchecked -> include.
            ViewModel.ToggleGroupIncludedFromClick(row.MemberIds);
        }
        finally
        {
            _syncingSelection = false;
        }

        SyncNativeSelectionFromViewModel();
        RefreshScope();
        SyncInclusionChecks();
    }

    private void ComputerCheck_Click(object sender, RoutedEventArgs e)
    {
        if (_syncingChecks || ViewModel is null || sender is not CheckBox box)
        {
            return;
        }

        if (box.Tag is not ComputerTile tile)
        {
            return;
        }

        _syncingSelection = true;
        try
        {
            ViewModel.SetComputerIncluded(tile.Id, box.IsChecked == true);
        }
        finally
        {
            _syncingSelection = false;
        }

        SyncNativeSelectionFromViewModel();
        RefreshScope();
        SyncInclusionChecks();
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        ViewModel.ClearSelection();
        SyncNativeSelectionFromViewModel();
        RefreshScope();
    }

    private void ClearFilters_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        _syncingSelection = true;
        try
        {
            ViewModel.ClearFilters();
        }
        finally
        {
            _syncingSelection = false;
        }

        SearchBox.Text = string.Empty;
        StatusFilterBox.SelectedIndex = 0;
        SyncNativeSelectionFromViewModel();
        RefreshScope();
    }

    private void ChooseComputers_Click(object sender, RoutedEventArgs e)
    {
        ViewModel?.ChooseComputers();
        PanelToggle.IsChecked = true;
    }

    private void PanelToggle_Checked(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;
        ViewModel.IsComputersPanelExpanded = true;
        ComputersPanel.Visibility = Visibility.Visible;
        ComputersPanel.IsExpanded = true;
    }

    private void PanelToggle_Unchecked(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;
        ViewModel.IsComputersPanelExpanded = false;
        ComputersPanel.Visibility = Visibility.Collapsed;
    }

    private void ComputersPanel_Collapsed(Expander sender, ExpanderCollapsedEventArgs args)
    {
        PanelToggle.IsChecked = false;
    }

    private void PreviewSize_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null || sender is not MenuFlyoutItem { Tag: string tag })
        {
            return;
        }

        var size = tag switch
        {
            "Compact192" => PreviewSize.Compact192,
            "Standard256" => PreviewSize.Standard256,
            "ExtraLarge448" => PreviewSize.ExtraLarge448,
            _ => PreviewSize.Large320,
        };

        // Density reflow must not reset selection, filters, or inclusion.
        ViewModel.PreviewSize = size;
    }

    private void GridListToggle_Checked(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        ViewModel.IsGridView = true;
        ApplyLayoutChrome();
    }

    private void GridListToggle_Unchecked(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        ViewModel.IsGridView = false;
        ApplyLayoutChrome();
    }

    private void PauseResume_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        ViewModel.ToggleMonitoringPause();
        RefreshScope();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        _pageLoadCts?.Cancel();
        _pageLoadCts?.Dispose();
        _pageLoadCts = new CancellationTokenSource();
        await RunPageInventoryLoadAsync(_pageLoadCts.Token);
    }

    private void InventoryHost_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncingSelection || _syncingTiles || ViewModel is null)
        {
            return;
        }

        _syncingSelection = true;
        try
        {
            // Native Extended selection supplies single/modifier/range and
            // keyboard equivalents. Map onto the domain selection model
            // without rebuilding tile objects.
            var ids = InventoryHost.SelectedItems
                .OfType<ComputerTile>()
                .Select(t => t.Id)
                .ToList();
            ViewModel.ApplyNativeSelection(ids);
        }
        finally
        {
            _syncingSelection = false;
        }

        RefreshScope();
    }

    private void InventoryHost_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        OpenViewScreenForTarget(FindTile(e.OriginalSource as DependencyObject));
    }

    private void InventoryHost_RightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        var tile = FindTile(e.OriginalSource as DependencyObject);
        if (tile is not null && !ViewModel.Overview.Selection.IsSelected(tile.Id))
        {
            ViewModel.SelectTile(tile.Id, additive: false);
            SyncNativeSelectionFromViewModel();
            RefreshScope();
        }

        if (InventoryHost.ContextFlyout is MenuFlyout flyout)
        {
            flyout.ShowAt(InventoryHost, new Microsoft.UI.Xaml.Controls.Primitives.FlyoutShowOptions { Position = e.GetPosition(InventoryHost) });
            e.Handled = true;
        }
    }

    private void InventoryHost_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        if (e.Key == Windows.System.VirtualKey.Enter)
        {
            // Activate the focused tile, not an arbitrary first selection.
            var focused = FindTile(FocusManager.GetFocusedElement(XamlRoot) as DependencyObject);
            OpenViewScreenForTarget(focused ?? FindFocusedOrSelectedTile());
            e.Handled = true;
            return;
        }

        // Keyboard context menu: Application key or Shift+F10.
        if (e.Key == Windows.System.VirtualKey.Application)
        {
            if (InventoryHost.ContextFlyout is MenuFlyout menu)
            {
                menu.ShowAt(InventoryHost);
                e.Handled = true;
            }
        }
    }

    private void ViewScreen_Click(object sender, RoutedEventArgs e)
    {
        OpenViewScreenForTarget(FindFocusedOrSelectedTile());
    }

    private ComputerTile? FindFocusedOrSelectedTile()
    {
        if (ViewModel is null)
        {
            return null;
        }

        var focused = FindTile(FocusManager.GetFocusedElement(XamlRoot) as DependencyObject);
        if (focused is not null)
        {
            return focused;
        }

        // Prefer the anchor/last-selected id when present.
        var selected = ViewModel.Overview.Selection.SelectedIds;
        foreach (var id in selected)
        {
            var tile = ViewModel.AllAuthorizedTiles.FirstOrDefault(t => t.Id == id);
            if (tile is not null)
            {
                return tile;
            }
        }

        return null;
    }

    private void OpenViewScreenForTarget(ComputerTile? tile)
    {
        if (ViewModel is null || tile is null)
        {
            return;
        }

        (Application.Current as App)?.ViewerWindows?.Open(tile.Id);
    }

    private ComputerTile? FindTile(DependencyObject? source)
    {
        var current = source;
        while (current is not null)
        {
            if (current is ListViewItem { Content: ComputerTile tile })
            {
                return tile;
            }

            if (current is ContentPresenter { Content: ComputerTile contentTile })
            {
                return contentTile;
            }

            current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    /// <summary>
    /// Push domain selection onto the native list under a guard so
    /// SelectionChanged cannot reinstall selection the domain just cleared.
    /// </summary>
    private void SyncNativeSelectionFromViewModel()
    {
        if (ViewModel is null)
        {
            return;
        }

        _syncingSelection = true;
        _syncingTiles = true;
        try
        {
            InventoryHost.SelectedItems.Clear();
            foreach (var tile in ViewModel.Tiles)
            {
                if (ViewModel.Overview.Selection.IsSelected(tile.Id))
                {
                    InventoryHost.SelectedItems.Add(tile);
                }
            }
        }
        finally
        {
            _syncingTiles = false;
            _syncingSelection = false;
        }
    }
}
