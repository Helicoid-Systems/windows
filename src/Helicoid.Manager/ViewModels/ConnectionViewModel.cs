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

    /// <summary>Device-key challenge pending a six-digit TOTP code.</summary>
    AwaitingTotp = 6,
}

/// <summary>
/// Sign-in and session state for the manager. Development loopback access is
/// available only when the process was started with an explicit development
/// server option. Production device-key challenge sign-in requires real
/// supplied authority trust; when absent the UI stays explicitly closed.
/// </summary>
public sealed class ConnectionViewModel : INotifyPropertyChanged, IDisposable
{
    private string _statusMessage = string.Empty;
    private string _detailMessage = string.Empty;
    private ConnectionUiState _state = ConnectionUiState.ProductionClosed;
    private string _username = string.Empty;
    private string _managerIdentity = string.Empty;
    private string _signedInAccountName = string.Empty;
    private string _managerLifecycleState = string.Empty;
    private bool _isDevelopmentEnabled;
    private bool _requiresTotp;
    private bool _disposed;
    private readonly SynchronizationContext? _notifyContext;

    public ConnectionViewModel(
        DevelopmentLaunchOptions launchOptions,
        IHsServerClient client,
        V2SignInCoordinator? deviceKeySignIn = null)
    {
        ArgumentNullException.ThrowIfNull(launchOptions);
        ArgumentNullException.ThrowIfNull(client);
        LaunchOptions = launchOptions;
        Client = client;
        DeviceKeySignIn = deviceKeySignIn;
        _isDevelopmentEnabled = launchOptions.DevelopmentServerEnabled;
        _managerIdentity = launchOptions.DevelopmentManagerIdentity ?? string.Empty;
        _notifyContext = SynchronizationContext.Current;

        if (deviceKeySignIn is not null)
        {
            _state = ConnectionUiState.ReadyForDevelopmentSignin;
            _statusMessage = deviceKeySignIn.StatusMessage;
            _detailMessage = deviceKeySignIn.DetailMessage;
            deviceKeySignIn.PropertyChanged += OnDeviceKeySignInChanged;
            deviceKeySignIn.SessionIdentityChanged += OnDeviceKeySessionIdentityChanged;
        }
        else if (!launchOptions.DevelopmentServerEnabled)
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

    /// <summary>
    /// Raised when an established session is lost (automatic expiry or
    /// sign-out) so owners can drop session-scoped inventory and selection.
    /// </summary>
    public event EventHandler? SessionLost;

    /// <summary>
    /// Generation-fenced session identity transition from the sign-in
    /// coordinator. Applied on the UI synchronization context so queued Phase
    /// snapshots cannot hide a lost or replaced identity.
    /// </summary>
    public event EventHandler<SessionIdentityChangedEventArgs>? SessionIdentityChanged;

    public DevelopmentLaunchOptions LaunchOptions { get; }

    public IHsServerClient Client { get; }

    /// <summary>
    /// Production device-key challenge sign-in. Null when authority trust is
    /// not configured for this process.
    /// </summary>
    public V2SignInCoordinator? DeviceKeySignIn { get; }

    public bool IsDevelopmentEnabled
    {
        get => _isDevelopmentEnabled;
        private set { _isDevelopmentEnabled = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanSignIn)); }
    }

    /// <summary>True when a six-digit TOTP code must be collected.</summary>
    public bool RequiresTotp
    {
        get => _requiresTotp;
        private set
        {
            _requiresTotp = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanSignIn));
        }
    }

    public bool CanSignIn
    {
        get
        {
            if (DeviceKeySignIn is not null)
            {
                return DeviceKeySignIn.CanStart || DeviceKeySignIn.CanCompleteTotp;
            }

            return IsDevelopmentEnabled
                && _state is not (ConnectionUiState.SigningIn or ConnectionUiState.SignedIn);
        }
    }

    public string Username
    {
        get => _username;
        set
        {
            _username = value;
            if (DeviceKeySignIn is not null)
            {
                DeviceKeySignIn.Username = value;
            }

            OnPropertyChanged();
        }
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

    public string SignedInAccountName
    {
        get => _signedInAccountName;
        private set
        {
            if (_signedInAccountName == value)
            {
                return;
            }

            _signedInAccountName = value;
            OnPropertyChanged();
        }
    }

    public string ManagerLifecycleState
    {
        get => _managerLifecycleState;
        private set
        {
            if (_managerLifecycleState == value)
            {
                return;
            }

            _managerLifecycleState = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (DeviceKeySignIn is not null)
        {
            DeviceKeySignIn.PropertyChanged -= OnDeviceKeySignInChanged;
            DeviceKeySignIn.SessionIdentityChanged -= OnDeviceKeySessionIdentityChanged;
        }

        SessionLost = null;
        SessionIdentityChanged = null;
    }

    public async Task SignInAsync(string password, CancellationToken cancellationToken)
    {
        if (DeviceKeySignIn is not null)
        {
            await DeviceKeySignIn.SignInAsync(password, cancellationToken).ConfigureAwait(true);
            return;
        }

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

    /// <summary>Submit a six-digit TOTP code for a pending device-key challenge.</summary>
    public async Task SubmitTotpAsync(string? totpCode, CancellationToken cancellationToken)
    {
        if (DeviceKeySignIn is null)
        {
            return;
        }

        await DeviceKeySignIn.CompleteWithTotpAsync(totpCode, cancellationToken).ConfigureAwait(true);
    }

    public void CancelSignIn()
    {
        DeviceKeySignIn?.Cancel();
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
            // Inventory refresh is secondary. A failed fetch must not clobber
            // an established session with a production-closed transition.
            if (ex.Failure is not (ServerClientFailure.NotAvailableInThisBuild
                or ServerClientFailure.NotConnected
                or ServerClientFailure.Cancelled))
            {
                ApplyFailure(ex);
            }
        }
    }

    public async Task SignOutAsync(CancellationToken cancellationToken)
    {
        if (DeviceKeySignIn is not null)
        {
            DeviceKeySignIn.SignOut();
            return;
        }

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
        var wasSignedIn = State == ConnectionUiState.SignedIn;
        State = IsDevelopmentEnabled
            ? ConnectionUiState.ReadyForDevelopmentSignin
            : ConnectionUiState.ProductionClosed;
        StatusMessage = IsDevelopmentEnabled
            ? "Signed out."
            : "Server sign-in is not available in this build.";
        DetailMessage = string.Empty;
        if (wasSignedIn)
        {
            SessionLost?.Invoke(this, EventArgs.Empty);
        }
    }

    private void OnDeviceKeySignInChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (DeviceKeySignIn is null || _disposed)
        {
            return;
        }

        // Coordinating property updates may arrive from a deadline timer.
        // Marshal to the captured UI synchronization context when present.
        if (_notifyContext is not null && SynchronizationContext.Current != _notifyContext)
        {
            _notifyContext.Post(_ => ApplyDeviceKeySignInChange(e), null);
            return;
        }

        ApplyDeviceKeySignInChange(e);
    }

    private void OnDeviceKeySessionIdentityChanged(object? sender, SessionIdentityChangedEventArgs e)
    {
        if (_disposed)
        {
            return;
        }

        // Identity transitions must be applied at the UI seam even when Phase
        // events are coalesced or an old notification is skipped.
        if (_notifyContext is not null && SynchronizationContext.Current != _notifyContext)
        {
            _notifyContext.Post(_ => ApplySessionIdentityChange(e), null);
            return;
        }

        ApplySessionIdentityChange(e);
    }

    private void ApplySessionIdentityChange(SessionIdentityChangedEventArgs e)
    {
        if (_disposed)
        {
            return;
        }

        // Generation-fenced identity transition. SessionLost remains a
        // compatibility signal for observers; MainViewModel scopes cleanup to
        // legacy/no-v2 so a generic loss cannot erase a replacement's inventory.
        SessionIdentityChanged?.Invoke(this, e);
        if (e.OldGeneration != 0 && e.NewGeneration != e.OldGeneration)
        {
            SessionLost?.Invoke(this, EventArgs.Empty);
        }
    }

    private void ApplyDeviceKeySignInChange(PropertyChangedEventArgs e)
    {
        if (DeviceKeySignIn is null || _disposed)
        {
            return;
        }

        switch (e.PropertyName)
        {
            case nameof(V2SignInCoordinator.Phase):
                State = DeviceKeySignIn.Phase switch
                {
                    V2SignInPhase.Unavailable => ConnectionUiState.ProductionClosed,
                    V2SignInPhase.Ready => ConnectionUiState.ReadyForDevelopmentSignin,
                    V2SignInPhase.StartingChallenge => ConnectionUiState.SigningIn,
                    V2SignInPhase.AwaitingTotp => ConnectionUiState.AwaitingTotp,
                    V2SignInPhase.Completing => ConnectionUiState.SigningIn,
                    V2SignInPhase.SignedIn => ConnectionUiState.SignedIn,
                    V2SignInPhase.Refused => ConnectionUiState.Refused,
                    V2SignInPhase.Failed => ConnectionUiState.Failed,
                    _ => ConnectionUiState.Failed,
                };
                SignedInAccountName = DeviceKeySignIn.SignedInAccountName;
                ManagerLifecycleState = DeviceKeySignIn.ManagerLifecycleState;
                RequiresTotp = DeviceKeySignIn.RequiresTotp;
                // Device-key loss is generation-fenced via SessionIdentityChanged.
                // Generic SessionLost remains for legacy/no-v2 sign-out only.
                break;
            case nameof(V2SignInCoordinator.RequiresTotp):
                RequiresTotp = DeviceKeySignIn.RequiresTotp;
                break;
            case nameof(V2SignInCoordinator.StatusMessage):
                StatusMessage = DeviceKeySignIn.StatusMessage;
                break;
            case nameof(V2SignInCoordinator.DetailMessage):
                DetailMessage = DeviceKeySignIn.DetailMessage;
                break;
            case nameof(V2SignInCoordinator.SignedInAccountName):
                SignedInAccountName = DeviceKeySignIn.SignedInAccountName;
                break;
            case nameof(V2SignInCoordinator.ManagerLifecycleState):
                ManagerLifecycleState = DeviceKeySignIn.ManagerLifecycleState;
                break;
            case nameof(V2SignInCoordinator.CanStart):
            case nameof(V2SignInCoordinator.CanCompleteTotp):
                OnPropertyChanged(nameof(CanSignIn));
                break;
        }
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
