using System.ComponentModel;
using Helicoid.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace Helicoid.Manager.Views;

public sealed partial class ConnectionPage : Page
{
    private ConnectionViewModel? _viewModel;
    private CancellationTokenSource? _pageLifetime;
    private bool _submitting;

    public ConnectionPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is not ConnectionViewModel vm) return;
        _viewModel = vm;
        _pageLifetime = new CancellationTokenSource();
        UsernameBox.Text = vm.Username;
        ManagerIdentityBox.Text = vm.ManagerIdentity;
        vm.PropertyChanged += OnModelChanged;
        Refresh();
        Loaded += FocusInitialField;
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        Loaded -= FocusInitialField;
        if (_viewModel is { } vm)
        {
            vm.PropertyChanged -= OnModelChanged;
            if (vm.State is ConnectionUiState.SigningIn or ConnectionUiState.AwaitingTotp)
                vm.CancelSignIn();
        }
        _pageLifetime?.Cancel();
        _pageLifetime?.Dispose();
        _pageLifetime = null;
        _viewModel = null;
        ClearSecrets();
        base.OnNavigatedFrom(e);
    }

    private void FocusInitialField(object sender, RoutedEventArgs e)
    {
        if (UsernameBox.IsEnabled) UsernameBox.Focus(FocusState.Programmatic);
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_viewModel?.State is ConnectionUiState.ProductionClosed or ConnectionUiState.SignedIn)
            ClearSecrets();
        Refresh();
    }

    private void Refresh()
    {
        if (_viewModel is not { } vm) return;
        var closed = vm.State == ConnectionUiState.ProductionClosed;
        var signedIn = vm.State == ConnectionUiState.SignedIn;
        var awaitingCode = vm.State == ConnectionUiState.AwaitingTotp && vm.RequiresTotp;
        var signingIn = vm.State == ConnectionUiState.SigningIn;
        TaskTitle.Text = awaitingCode ? "Verification Code" : closed ? "Connect to Server" : "Sign In";
        StatusText.Text = closed ? "Connecting requires a verified connection profile." : vm.StatusMessage.TrimEnd('…');
        DetailText.Text = vm.DetailMessage;
        Details.Visibility = string.IsNullOrWhiteSpace(vm.DetailMessage) ? Visibility.Collapsed : Visibility.Visible;
        CredentialFields.Visibility = closed || signedIn || awaitingCode ? Visibility.Collapsed : Visibility.Visible;
        UsernameBox.IsEnabled = vm.CanSignIn && !_submitting;
        PasswordBox.IsEnabled = UsernameBox.IsEnabled;
        ManagerIdentityBox.Visibility = vm.IsDevelopmentEnabled && vm.DeviceKeySignIn is null ? Visibility.Visible : Visibility.Collapsed;
        ManagerIdentityBox.IsEnabled = UsernameBox.IsEnabled;
        TotpPanel.Visibility = awaitingCode ? Visibility.Visible : Visibility.Collapsed;
        TotpBox.IsEnabled = awaitingCode && !_submitting;
        SignInButton.Visibility = closed || signedIn || awaitingCode ? Visibility.Collapsed : Visibility.Visible;
        SignInButton.IsEnabled = vm.CanSignIn && !_submitting
            && !string.IsNullOrWhiteSpace(UsernameBox.Text) && !string.IsNullOrEmpty(PasswordBox.Password);
        SubmitTotpButton.Visibility = awaitingCode ? Visibility.Visible : Visibility.Collapsed;
        SubmitTotpButton.IsEnabled = awaitingCode && !_submitting && !string.IsNullOrEmpty(TotpBox.Password);
        SignOutButton.Visibility = signedIn ? Visibility.Visible : Visibility.Collapsed;
        SignOutButton.IsEnabled = !_submitting;
        CancelButton.Visibility = signingIn || awaitingCode ? Visibility.Visible : Visibility.Collapsed;
        Activity.IsActive = signingIn || _submitting;
        Activity.Visibility = Activity.IsActive ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UsernameBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_viewModel is { } vm) vm.Username = UsernameBox.Text;
        Refresh();
    }

    private void ManagerIdentityBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_viewModel is { } vm) vm.ManagerIdentity = ManagerIdentityBox.Text;
    }

    private void Secret_Changed(object sender, RoutedEventArgs e) => Refresh();

    private void ClearSecrets()
    {
        PasswordBox.Password = string.Empty;
        TotpBox.Password = string.Empty;
    }

    private async Task SubmitAsync(bool code)
    {
        if (_viewModel is not { } vm || _pageLifetime is not { } lifetime || _submitting) return;
        if (code ? !SubmitTotpButton.IsEnabled : !SignInButton.IsEnabled) return;
        var secret = code ? TotpBox.Password : PasswordBox.Password;
        ClearSecrets();
        _submitting = true;
        Refresh();
        try
        {
            if (code) await vm.SubmitTotpAsync(secret, lifetime.Token);
            else await vm.SignInAsync(secret, lifetime.Token);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally
        {
            _submitting = false;
            if (ReferenceEquals(_pageLifetime, lifetime)) Refresh();
        }
    }

    private async void SignIn_Click(object sender, RoutedEventArgs e) => await SubmitAsync(false);
    private async void SubmitTotp_Click(object sender, RoutedEventArgs e) => await SubmitAsync(true);

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _viewModel?.CancelSignIn();
        ClearSecrets();
        Refresh();
    }

    private async void SignOut_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is not { } vm || _pageLifetime is not { } lifetime || _submitting) return;
        ClearSecrets();
        _submitting = true;
        Refresh();
        try { await vm.SignOutAsync(lifetime.Token); }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally
        {
            _submitting = false;
            if (ReferenceEquals(_pageLifetime, lifetime)) Refresh();
        }
    }

    private async void Page_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Escape && CancelButton.Visibility == Visibility.Visible)
        {
            Cancel_Click(sender, e);
            e.Handled = true;
        }
        else if (e.Key == Windows.System.VirtualKey.Enter)
        {
            e.Handled = true;
            await SubmitAsync(_viewModel?.State == ConnectionUiState.AwaitingTotp);
        }
    }
}
