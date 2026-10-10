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
            Refresh();
        }
    }

    private void Refresh()
    {
        if (_viewModel is null)
        {
            return;
        }

        var enabled = _viewModel.IsDevelopmentEnabled;
        UsernameBox.IsEnabled = enabled && _viewModel.CanSignIn;
        PasswordBox.IsEnabled = enabled && _viewModel.CanSignIn;
        ManagerIdentityBox.IsEnabled = enabled && _viewModel.CanSignIn;
        SignInButton.IsEnabled = _viewModel.CanSignIn;
        SignOutButton.IsEnabled = enabled && _viewModel.State == ConnectionUiState.SignedIn;

        ModeInfo.Message = _viewModel.StatusMessage;
        ModeInfo.Severity = _viewModel.State switch
        {
            ConnectionUiState.ProductionClosed => InfoBarSeverity.Informational,
            ConnectionUiState.Refused => InfoBarSeverity.Error,
            ConnectionUiState.Failed => InfoBarSeverity.Warning,
            ConnectionUiState.SignedIn => InfoBarSeverity.Success,
            _ => InfoBarSeverity.Informational,
        };
        ModeInfo.Title = _viewModel.State switch
        {
            ConnectionUiState.ProductionClosed => "Not available",
            ConnectionUiState.ReadyForDevelopmentSignin => "Development server",
            ConnectionUiState.SigningIn => "Signing in",
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

    private async void SignOut_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        await _viewModel.SignOutAsync(CancellationToken.None);
        Refresh();
    }
}
