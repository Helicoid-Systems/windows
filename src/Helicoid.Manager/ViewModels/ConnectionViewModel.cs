using System.ComponentModel;
using System.Runtime.CompilerServices;
using Helicoid.Domain.Client;
using Helicoid.Domain.Model;

namespace Helicoid.Manager.ViewModels;

public enum ConnectionUiState
{
    ProductionClosed = 0,
    ReadyForDevelopmentSignin = 1,
    SigningIn = 2,
    SignedIn = 3,
    Refused = 4,
    Failed = 5,
}

/// <summary>
/// Sign-in and session state for the manager. Development loopback access is
/// available only when the process was started with an explicit development
/// server option. Default remains the closed production client.
/// </summary>
public sealed class ConnectionViewModel : INotifyPropertyChanged
{
    private string _statusMessage = string.Empty;
    private string _detailMessage = string.Empty;
    private ConnectionUiState _state = ConnectionUiState.ProductionClosed;
    private string _username = string.Empty;
    private string _managerIdentity = string.Empty;
    private bool _isDevelopmentEnabled;

    public ConnectionViewModel(DevelopmentLaunchOptions launchOptions, IHsServerClient client)
    {
        ArgumentNullException.ThrowIfNull(launchOptions);
        ArgumentNullException.ThrowIfNull(client);
        LaunchOptions = launchOptions;
        Client = client;
        _isDevelopmentEnabled = launchOptions.DevelopmentServerEnabled;
        _managerIdentity = launchOptions.DevelopmentManagerIdentity ?? string.Empty;

        if (!launchOptions.DevelopmentServerEnabled)
        {
            _state = ConnectionUiState.ProductionClosed;
            _statusMessage = "Server sign-in is not available in this build.";
            _detailMessage = "Start the manager with the development server option to connect to a local development server.";
        }
        else
        {
            _state = ConnectionUiState.ReadyForDevelopmentSignin;
            _statusMessage = "Development server mode";
            _detailMessage = "Sign in to the local development server. Manager identity is a development label, not a production identity.";
        }
    }

    public DevelopmentLaunchOptions LaunchOptions { get; }

    public IHsServerClient Client { get; }

    public bool IsDevelopmentEnabled
    {
        get => _isDevelopmentEnabled;
        private set { _isDevelopmentEnabled = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanSignIn)); }
    }

    public bool CanSignIn => IsDevelopmentEnabled
        && _state is not (ConnectionUiState.SigningIn or ConnectionUiState.SignedIn);

    public string Username
    {
        get => _username;
        set { _username = value; OnPropertyChanged(); }
    }

    /// <summary>
    /// Optional development manager identity string. Operator-chosen label for
    /// the loopback development server; never a cryptographic identity.
    /// </summary>
    public string ManagerIdentity
    {
        get => _managerIdentity;
        set { _managerIdentity = value; OnPropertyChanged(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set { _statusMessage = value; OnPropertyChanged(); }
    }

    public string DetailMessage
    {
        get => _detailMessage;
        private set { _detailMessage = value; OnPropertyChanged(); }
    }

    public ConnectionUiState State
    {
        get => _state;
        private set
        {
            _state = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanSignIn));
        }
    }

    public string SignedInAccountName { get; private set; } = string.Empty;

    public string ManagerLifecycleState { get; private set; } = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public async Task SignInAsync(string password, CancellationToken cancellationToken)
    {
        if (!IsDevelopmentEnabled)
        {
            State = ConnectionUiState.Refused;
            StatusMessage = "Sign-in is not available in this build.";
            return;
        }

        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrEmpty(password))
        {
            State = ConnectionUiState.Failed;
            StatusMessage = "Enter a username and password.";
            return;
        }

        State = ConnectionUiState.SigningIn;
        StatusMessage = "Signing in…";
        DetailMessage = string.Empty;

        try
        {
            var login = await Client.LoginAsync(
                Username,
                password,
                string.IsNullOrWhiteSpace(ManagerIdentity) ? null : ManagerIdentity.Trim(),
                cancellationToken).ConfigureAwait(true);

            SignedInAccountName = login.Account?.Username ?? Username;
            ManagerLifecycleState = login.Manager?.LifecycleState ?? "none";
            State = ConnectionUiState.SignedIn;
            StatusMessage = $"Signed in as {SignedInAccountName}";
            DetailMessage = DescribeManager(ManagerLifecycleState);
        }
        catch (ServerClientException ex)
        {
            ApplyFailure(ex);
        }
    }

    public async Task RefreshInventoryAsync(
        Action<IReadOnlyList<ComputerRecord>> apply,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(apply);
        try
        {
            var inventory = await Client.GetInventoryAsync(cancellationToken).ConfigureAwait(true);
            apply(inventory);
        }
        catch (ServerClientException ex)
        {
            ApplyFailure(ex);
        }
    }

    public async Task SignOutAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Client.LogoutAsync(cancellationToken).ConfigureAwait(true);
        }
        catch (ServerClientException ex)
        {
            ApplyFailure(ex);
            return;
        }

        SignedInAccountName = string.Empty;
        ManagerLifecycleState = string.Empty;
        State = IsDevelopmentEnabled
            ? ConnectionUiState.ReadyForDevelopmentSignin
            : ConnectionUiState.ProductionClosed;
        StatusMessage = IsDevelopmentEnabled
            ? "Signed out."
            : "Server sign-in is not available in this build.";
        DetailMessage = string.Empty;
    }

    private void ApplyFailure(ServerClientException ex)
    {
        // Never echo credentials or tokens. The exception messages are safe.
        switch (ex.Failure)
        {
            case ServerClientFailure.Unauthorized:
                State = ConnectionUiState.Refused;
                StatusMessage = "Sign-in failed.";
                DetailMessage = "Check the username and password.";
                break;
            case ServerClientFailure.Forbidden:
                State = ConnectionUiState.Refused;
                StatusMessage = "Access refused.";
                DetailMessage = DescribeForbidden(ex);
                break;
            case ServerClientFailure.RateLimited:
                State = ConnectionUiState.Refused;
                StatusMessage = "Too many sign-in attempts.";
                DetailMessage = "Wait and try again.";
                break;
            case ServerClientFailure.SecurityStateUnavailable:
                State = ConnectionUiState.Failed;
                StatusMessage = "Server cannot accept new sign-ins right now.";
                DetailMessage = "Trusted storage is unavailable on the server. Contact your administrator.";
                break;
            case ServerClientFailure.NotAvailableInThisBuild:
                State = ConnectionUiState.ProductionClosed;
                StatusMessage = "Server sign-in is not available in this build.";
                DetailMessage = ex.Message;
                break;
            case ServerClientFailure.NotLoopback:
            case ServerClientFailure.InvalidAddress:
            case ServerClientFailure.RedirectRefused:
                State = ConnectionUiState.Failed;
                StatusMessage = "Development server address is not allowed.";
                DetailMessage = "Use a local loopback address only.";
                break;
            case ServerClientFailure.Timeout:
            case ServerClientFailure.TransportFailed:
                State = ConnectionUiState.Failed;
                StatusMessage = "Could not reach the development server.";
                DetailMessage = "Confirm the local server is running.";
                break;
            default:
                State = ConnectionUiState.Failed;
                StatusMessage = "Something went wrong.";
                DetailMessage = ex.Message;
                break;
        }
    }

    private static string DescribeManager(string lifecycleState) => lifecycleState switch
    {
        "approved" => "This manager is approved.",
        "pending" => "This manager is waiting for administrator approval.",
        "revoked" => "This manager has been revoked.",
        _ => string.Empty,
    };

    private static string DescribeForbidden(ServerClientException ex)
    {
        var message = ex.Message;
        if (message.Contains("pending", StringComparison.OrdinalIgnoreCase))
        {
            return "This manager is waiting for administrator approval.";
        }

        if (message.Contains("revoked", StringComparison.OrdinalIgnoreCase))
        {
            return "This manager has been revoked.";
        }

        return message;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
