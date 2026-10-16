using Helicoid.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Helicoid.Manager.Views;

public sealed partial class ConnectionPage : Page
{
    private ConnectionViewModel? _viewModel;

    public ConnectionPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is ConnectionViewModel vm)
        {
            _viewModel = vm;
            ManagerIdentityBox.Text = vm.ManagerIdentity;
            vm.PropertyChanged += (_, _) => Refresh();
            Refresh();
        }
    }

    private void Refresh()
    {
        if (_viewModel is null)
        {
            return;
        }

        var deviceKey = _viewModel.DeviceKeySignIn is not null;
        var awaitingTotp = _viewModel.RequiresTotp
            && _viewModel.State == ConnectionUiState.AwaitingTotp;

        UsernameBox.IsEnabled = _viewModel.CanSignIn && !awaitingTotp;
        PasswordBox.IsEnabled = _viewModel.CanSignIn && !awaitingTotp;
        ManagerIdentityBox.IsEnabled = _viewModel.IsDevelopmentEnabled && _viewModel.CanSignIn && !awaitingTotp;
        SignInButton.IsEnabled = _viewModel.CanSignIn && !awaitingTotp;
        CancelButton.IsEnabled = deviceKey
            && _viewModel.State is ConnectionUiState.SigningIn
                or ConnectionUiState.AwaitingTotp;
        SignOutButton.IsEnabled = _viewModel.State == ConnectionUiState.SignedIn;

        TotpPanel.Visibility = awaitingTotp ? Visibility.Visible : Visibility.Collapsed;
        TotpBox.IsEnabled = awaitingTotp;
        SubmitTotpButton.IsEnabled = awaitingTotp;

        ModeInfo.Message = _viewModel.StatusMessage;
        ModeInfo.Severity = _viewModel.State switch
        {
            ConnectionUiState.ProductionClosed => InfoBarSeverity.Informational,
            ConnectionUiState.Refused => InfoBarSeverity.Error,
            ConnectionUiState.Failed => InfoBarSeverity.Warning,
            ConnectionUiState.SignedIn => InfoBarSeverity.Success,
            ConnectionUiState.AwaitingTotp => InfoBarSeverity.Warning,
            _ => InfoBarSeverity.Informational,
        };
        ModeInfo.Title = _viewModel.State switch
        {
            ConnectionUiState.ProductionClosed => "Not available",
            ConnectionUiState.ReadyForDevelopmentSignin when deviceKey => "Device-key sign-in",
            ConnectionUiState.ReadyForDevelopmentSignin => "Development server",
            ConnectionUiState.SigningIn => "Signing in",
            ConnectionUiState.AwaitingTotp => "Authentication code required",
            ConnectionUiState.SignedIn => "Signed in",
            ConnectionUiState.Refused => "Access refused",
            ConnectionUiState.Failed => "Connection problem",
            _ => "Server access",
        };

        StatusText.Text = _viewModel.StatusMessage;
        DetailText.Text = _viewModel.DetailMessage;
    }

    private void UsernameBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_viewModel is not null)
        {
            _viewModel.Username = UsernameBox.Text;
        }
    }

    private void ManagerIdentityBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_viewModel is not null)
        {
            _viewModel.ManagerIdentity = ManagerIdentityBox.Text;
        }
    }

    private async void SignIn_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        await _viewModel.SignInAsync(PasswordBox.Password, CancellationToken.None);
        // Password is not retained on the view model.
        PasswordBox.Password = string.Empty;
        Refresh();
    }

    private async void SubmitTotp_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        var code = TotpBox.Password;
        TotpBox.Password = string.Empty;
        await _viewModel.SubmitTotpAsync(code, CancellationToken.None);
        Refresh();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _viewModel?.CancelSignIn();
        PasswordBox.Password = string.Empty;
        TotpBox.Password = string.Empty;
        Refresh();
    }

    private async void SignOut_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        await _viewModel.SignOutAsync(CancellationToken.None);
        PasswordBox.Password = string.Empty;
        TotpBox.Password = string.Empty;
        Refresh();
    }
}
