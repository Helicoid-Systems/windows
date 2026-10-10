using Helicoid.Domain.Model;
using Helicoid.Domain.Overview;
using Helicoid.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Helicoid.Manager.Views;

public sealed partial class ComputersPage : Page
{
    public MainViewModel ViewModel { get; private set; } = null!;

    public ComputersPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is MainViewModel vm)
        {
            ViewModel = vm;
            DataContext = vm;
            AllComputersCheck.IsChecked = vm.Overview.Inclusion.IsAllMode;
            RefreshScope();
        }
    }

    private void RefreshScope()
    {
        if (ViewModel is null)
        {
            return;
        }

        ScopeLine.Text = ViewModel.ScopeLine;
        var empty = ViewModel.Overview.DisplayedIds.Count == 0;
        EmptyState.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
        {
            ViewModel.OnSearchChanged(sender.Text);
            RefreshScope();
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
        ViewModel.OnStatusFilterChanged(filter);
        RefreshScope();
    }

    private void FixturesToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        ViewModel.SetFixtureMode(FixturesToggle.IsOn);
        RefreshScope();
    }

    private void AllComputersCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        ViewModel.ToggleInclusionAll();
        RefreshScope();
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.ClearSelection();
        RefreshScope();
    }

    private void GridListToggle_Checked(object sender, RoutedEventArgs e) => ViewModel.IsGridView = true;

    private void GridListToggle_Unchecked(object sender, RoutedEventArgs e) => ViewModel.IsGridView = false;

    private void PauseMonitoring_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.Overview.StopAllAdmittedStreams();
        RefreshScope();
    }

    private async void LoadServer_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        if (ViewModel.Connection.State != ConnectionUiState.SignedIn)
        {
            var dialog = new ContentDialog
            {
                Title = "Not signed in",
                Content = "Sign in on the Connection page first.",
                CloseButtonText = "Close",
                XamlRoot = XamlRoot,
            };
            await dialog.ShowAsync();
            return;
        }

        await ViewModel.Connection.RefreshInventoryAsync(
            inventory => ViewModel.ApplyServerInventory(inventory),
            CancellationToken.None);
        RefreshScope();
    }

    private async void SendFiles_Click(object sender, RoutedEventArgs e)
    {
        var snapshot = ViewModel.TryOpenAction("Send Files");
        await ShowSnapshotDialogAsync(snapshot, "Send Files");
    }

    private async void RequestFiles_Click(object sender, RoutedEventArgs e)
    {
        var snapshot = ViewModel.TryOpenAction("Request Files");
        await ShowSnapshotDialogAsync(snapshot, "Request Files");
    }

    private async void Screenshot_Click(object sender, RoutedEventArgs e)
    {
        var snapshot = ViewModel.TryOpenAction("Screenshot");
        await ShowSnapshotDialogAsync(snapshot, "Screenshot");
    }

    private async Task ShowSnapshotDialogAsync(ActionSnapshot? snapshot, string actionName)
    {
        var engineBlocked = !ViewModel.EngineStatus.IsAvailable;
        var body = snapshot is null
            ? "No computers displayed. Select computers or clear the search filter."
            : $"{actionName} targets {snapshot.Count} computer(s): {string.Join(", ", snapshot.DisplayNames)}. "
              + (engineBlocked
                  ? "Remote engine is unavailable in this build, so media-dependent commands cannot run."
                  : "Confirm the exact targets before dispatch.");

        var dialog = new ContentDialog
        {
            Title = actionName,
            Content = body,
            CloseButtonText = "Close",
            XamlRoot = XamlRoot,
        };
        await dialog.ShowAsync();
    }
}
