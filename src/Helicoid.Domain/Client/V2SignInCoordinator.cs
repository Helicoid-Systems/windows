using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Helicoid.Domain.Client;

/// <summary>Conditional TOTP sign-in phase for the native connection UI.</summary>
public enum V2SignInPhase
{
    /// <summary>No authority trust configured; production sign-in stays closed.</summary>
    Unavailable = 0,

    /// <summary>Ready for username/password challenge start.</summary>
    Ready = 1,

    /// <summary>Challenge begin is in flight.</summary>
    StartingChallenge = 2,

    /// <summary>Challenge is pending and requires a six-digit TOTP code.</summary>
    AwaitingTotp = 3,

    /// <summary>Challenge completion is in flight.</summary>
    Completing = 4,

    /// <summary>Session installed.</summary>
    SignedIn = 5,

    /// <summary>Server refused the attempt.</summary>
    Refused = 6,

    /// <summary>Transport/validation failure.</summary>
    Failed = 7,
}

/// <summary>Session identity transition. NewGeneration 0 means the identity was lost.</summary>
public sealed class SessionIdentityChangedEventArgs : EventArgs
{
    public SessionIdentityChangedEventArgs(int oldGeneration, int newGeneration)
    {
        OldGeneration = oldGeneration;
        NewGeneration = newGeneration;
    }

    public int OldGeneration { get; }

    public int NewGeneration { get; }
}

/// <summary>
/// Domain-level native sign-in state machine with conditional TOTP UI state.
/// Secrets (password, TOTP, pending challenge) stay in process memory only and
/// are cleared on cancel, sign-out, expiry, identity change, and dispose.
/// </summary>
public sealed class V2SignInCoordinator : INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private V2DeviceKeyChallengeClient? _client;
    private PendingAuthChallenge? _pending;
    private CancellationTokenSource? _activeCts;
    private int _activeOperation;

    /// <summary>
    /// Client session generation this coordinator last installed as SignedIn.
    /// Stale expiry notifications for any other generation cannot reset UI.
    /// </summary>
    private int _installedSessionGeneration;

    /// <summary>
    /// UI epoch bumped on every state-owning transition (sign-in start,
    /// install, cancel, sign-out, dispose, expiry reset). Queued UI dispatch
    /// captures the epoch and drops stale invalidations.
    /// </summary>
    private int _uiEpoch;

    private V2SignInPhase _phase = V2SignInPhase.Unavailable;
    private string _statusMessage = "Server sign-in is not available in this build.";
    private string _detailMessage = "Authority trust is not configured for this process.";
    private string _username = string.Empty;
    private string _signedInAccountName = string.Empty;
    private string _managerLifecycleState = string.Empty;
    private bool _requiresTotp;
    private bool _disposed;

    /// <summary>
    /// Create a coordinator. Pass a client built from real supplied authority
    /// trust; pass null to keep explicit production unavailability.
    /// </summary>
    public V2SignInCoordinator(V2DeviceKeyChallengeClient? client)
    {
        _client = client;
        if (client is null)
        {
            _phase = V2SignInPhase.Unavailable;
        }
        else
        {
            _phase = V2SignInPhase.Ready;
            _statusMessage = "Device-key sign-in";
            _detailMessage = "Sign in with your account password. A second factor may be required.";
            client.SessionExpired += OnClientSessionExpired;
        }
    }

    public V2SignInPhase Phase
    {
        get => _phase;
        private set
        {
            _phase = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanStart));
            OnPropertyChanged(nameof(CanCompleteTotp));
            OnPropertyChanged(nameof(RequiresTotp));
            OnPropertyChanged(nameof(IsSignedIn));
        }
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

    public string Username
    {
        get => _username;
        set { _username = value ?? string.Empty; OnPropertyChanged(); }
    }

    /// <summary>True when the TOTP field must be shown and submitted.</summary>
    public bool RequiresTotp
    {
        get => _requiresTotp;
        private set { _requiresTotp = value; OnPropertyChanged(); }
    }

    public bool CanStart => Phase is V2SignInPhase.Ready or V2SignInPhase.Refused or V2SignInPhase.Failed
        || (Phase is V2SignInPhase.AwaitingTotp);

    public bool CanCompleteTotp => Phase is V2SignInPhase.AwaitingTotp;

    public bool IsSignedIn => Phase is V2SignInPhase.SignedIn;

    public string SignedInAccountName
    {
        get => _signedInAccountName;
        private set { _signedInAccountName = value; OnPropertyChanged(); }
    }

    public string ManagerLifecycleState
    {
        get => _managerLifecycleState;
        private set { _managerLifecycleState = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// Generation-fenced session identity transition. Raised outside locks.
    /// UI layers must apply this at the application seam so a queued Phase
    /// snapshot cannot hide a lost or replaced identity.
    /// </summary>
    public event EventHandler<SessionIdentityChangedEventArgs>? SessionIdentityChanged;

    /// <summary>Installed session generation this coordinator last bound to UI, or 0.</summary>
    public int InstalledSessionGeneration
    {
        get
        {
            lock (_gate)
            {
                return _installedSessionGeneration;
            }
        }
    }

    /// <summary>
    /// Start a challenge. When the server marks MFA required (or omits the
    /// flag), the phase becomes <see cref="V2SignInPhase.AwaitingTotp"/> and
    /// the caller collects a six-digit code before
    /// <see cref="CompleteWithTotpAsync"/>. Optional non-enrolled login
    /// completes immediately.
    /// </summary>
    public async Task SignInAsync(string password, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(password);

        CancelPendingOperation();

        if (_client is null)
        {
            Phase = V2SignInPhase.Unavailable;
            StatusMessage = "Server sign-in is not available in this build.";
            DetailMessage = "Authority trust is not configured for this process.";
            return;
        }

        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrEmpty(password))
        {
            Phase = V2SignInPhase.Failed;
            StatusMessage = "Enter a username and password.";
            DetailMessage = string.Empty;
            RequiresTotp = false;
            return;
        }

        Phase = V2SignInPhase.StartingChallenge;
        StatusMessage = "Starting sign-in…";
        DetailMessage = string.Empty;
        RequiresTotp = false;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var operation = BeginOperation(cts);
        try
        {
            var pending = await _client.BeginChallengeAsync(Username, password, cts.Token)
                .ConfigureAwait(true);

            lock (_gate)
            {
                if (!IsCurrentOperation(operation))
                {
                    pending.Clear();
                    return;
                }

                _pending = pending;
            }

            if (pending.MfaRequired)
            {
                RequiresTotp = true;
                Phase = V2SignInPhase.AwaitingTotp;
                StatusMessage = "Enter your authentication code.";
                DetailMessage = "A six-digit code from your authenticator is required to finish signing in.";
                return;
            }

            // Optional non-enrolled path: complete without a factor code.
            await CompleteCoreAsync(pending, totpCode: null, operation).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (IsCurrentOperation(operation))
            {
                ResetToReady("Sign-in cancelled.", string.Empty);
                ClearSecrets();
            }
        }
        catch (OperationCanceledException)
        {
            if (IsCurrentOperation(operation))
            {
                ResetToReady("Sign-in timed out.", "The server did not respond in time.");
                ClearSecrets();
            }
        }
        catch (ServerClientException ex)
        {
            if (IsCurrentOperation(operation))
            {
                ClearSecrets();
                ApplyFailure(ex);
            }
        }
        catch (Exception ex)
        {
            if (IsCurrentOperation(operation))
            {
                ClearSecrets();
                Phase = V2SignInPhase.Failed;
                StatusMessage = "Something went wrong.";
                DetailMessage = ex.Message;
            }
        }
        finally
        {
            EndOperationIfCurrent(operation);
            cts.Dispose();
        }
    }

    /// <summary>Submit the six-digit code for a pending required-MFA challenge.</summary>
    public async Task CompleteWithTotpAsync(string? totpCode, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        PendingAuthChallenge? pending;
        lock (_gate)
        {
            pending = _pending;
        }

        if (pending is null || Phase is not V2SignInPhase.AwaitingTotp)
        {
            Phase = V2SignInPhase.Failed;
            StatusMessage = "There is no sign-in waiting for a code.";
            DetailMessage = string.Empty;
            return;
        }

        if (!IsSixDigitCode(totpCode))
        {
            Phase = V2SignInPhase.AwaitingTotp;
            StatusMessage = "Enter your authentication code.";
            DetailMessage = "The code must be six digits.";
            return;
        }

        Phase = V2SignInPhase.Completing;
        StatusMessage = "Verifying…";
        DetailMessage = string.Empty;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var operation = BeginOperation(cts);
        try
        {
            await CompleteCoreAsync(pending, totpCode, operation).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (IsCurrentOperation(operation))
            {
                ResetToReady("Sign-in cancelled.", string.Empty);
                ClearSecrets();
            }
        }
        catch (OperationCanceledException)
        {
            if (IsCurrentOperation(operation))
            {
                ResetToReady("Sign-in timed out.", "The server did not respond in time.");
                ClearSecrets();
            }
        }
        catch (ServerClientException ex)
        {
            if (IsCurrentOperation(operation))
            {
                // A refused factor returns to the TOTP prompt when the challenge
                // is still usable; otherwise the pending challenge is dropped.
                ClearSecrets();
                ApplyFailure(ex);
            }
        }
        catch (Exception ex)
        {
            if (IsCurrentOperation(operation))
            {
                ClearSecrets();
                Phase = V2SignInPhase.Failed;
                StatusMessage = "Something went wrong.";
                DetailMessage = ex.Message;
            }
        }
        finally
        {
            EndOperationIfCurrent(operation);
            cts.Dispose();
        }
    }

    /// <summary>
    /// Cancel any in-flight operation and drop pending secrets and any bearer
    /// the client may already have installed. A late UI continuation cannot
    /// observe SignedIn after cancel.
    /// </summary>
    public void Cancel()
    {
        CancelPendingOperation();
        ClearSecrets();
        _client?.ClearSession();
        SessionIdentityChangedEventArgs? lost = null;
        if (_client is not null && !_disposed)
        {
            lock (_gate)
            {
                if (_installedSessionGeneration != 0)
                {
                    lost = new SessionIdentityChangedEventArgs(_installedSessionGeneration, 0);
                }

                _installedSessionGeneration = 0;
                unchecked
                {
                    _uiEpoch++;
                }
            }

            Phase = V2SignInPhase.Ready;
            StatusMessage = "Sign-in cancelled.";
            DetailMessage = string.Empty;
            RequiresTotp = false;
            SignedInAccountName = string.Empty;
            ManagerLifecycleState = string.Empty;
            if (lost is not null)
            {
                SessionIdentityChanged?.Invoke(this, lost);
            }
        }
    }

    public void SignOut()
    {
        CancelPendingOperation();
        ClearSecrets();
        _client?.ClearSession();
        _client?.ClearPendingChallenge();
        SessionIdentityChangedEventArgs? lost = null;
        lock (_gate)
        {
            if (_installedSessionGeneration != 0)
            {
                lost = new SessionIdentityChangedEventArgs(_installedSessionGeneration, 0);
            }

            _installedSessionGeneration = 0;
            unchecked
            {
                _uiEpoch++;
            }
        }

        SignedInAccountName = string.Empty;
        ManagerLifecycleState = string.Empty;
        RequiresTotp = false;

        if (_client is null || _disposed)
        {
            Phase = V2SignInPhase.Unavailable;
            StatusMessage = "Server sign-in is not available in this build.";
            DetailMessage = "Authority trust is not configured for this process.";
        }
        else
        {
            Phase = V2SignInPhase.Ready;
            StatusMessage = "Signed out.";
            DetailMessage = string.Empty;
        }

        if (lost is not null)
        {
            SessionIdentityChanged?.Invoke(this, lost);
        }
    }

    public void Dispose()
    {
        V2DeviceKeyChallengeClient? client;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            client = _client;
            _client = null;
        }

        if (client is not null)
        {
            client.SessionExpired -= OnClientSessionExpired;
        }

        CancelPendingOperation();
        ClearSecrets();
        client?.Dispose();
    }

    /// <summary>
    /// Automatic bounded-deadline observation. Resets account, manager, TOTP,
    /// and connection status without another user action. Never logs a bearer.
    /// Fenced to this coordinator's installed session generation and the
    /// currently owned operation so a delayed old notification cannot erase a
    /// replacement sign-in, pending MFA completion, or newer UI.
    /// </summary>
    private void OnClientSessionExpired(object? sender, SessionExpiredEventArgs e)
    {
        V2DeviceKeyChallengeClient? client;
        int epoch;
        int lostGeneration;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            client = _client;

            // An in-flight sign-in/complete/cancel owns the UI. A stale expiry
            // for a previous generation must not cancel it.
            if (_activeCts is not null)
            {
                return;
            }

            // Only the exact generation this coordinator installed as SignedIn
            // may invalidate that UI. SessionGeneration is 0 while a replacement
            // is still completing, so it cannot be the fence.
            if (_installedSessionGeneration == 0
                || e.Generation != _installedSessionGeneration)
            {
                return;
            }

            // Established session loss only. Starting/AwaitingTotp/Completing
            // are owned by the current operation (guarded above).
            if (_phase is not V2SignInPhase.SignedIn)
            {
                return;
            }

            if (client is not null && client.IsSessionLive)
            {
                // Replacement already installed after the expired generation.
                return;
            }

            unchecked
            {
                _uiEpoch++;
            }

            epoch = _uiEpoch;
            lostGeneration = _installedSessionGeneration;
            _installedSessionGeneration = 0;

            // Atomic relative to sign-in/cancel/dispose: fields + Phase under
            // the same gate those transitions use.
            _pending?.Clear();
            _pending = null;
            _phase = V2SignInPhase.Ready;
            _statusMessage = "Your session expired. Sign in again.";
            _detailMessage = string.Empty;
            _requiresTotp = false;
            _signedInAccountName = string.Empty;
            _managerLifecycleState = string.Empty;
        }

        // Raise notifications outside the gate (no deadlock). Skip if a newer
        // transition took ownership while we were preparing this reset.
        lock (_gate)
        {
            if (_disposed || _uiEpoch != epoch)
            {
                return;
            }
        }

        SessionIdentityChanged?.Invoke(this, new SessionIdentityChangedEventArgs(lostGeneration, 0));
        OnPropertyChanged(nameof(Phase));
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanCompleteTotp));
        OnPropertyChanged(nameof(RequiresTotp));
        OnPropertyChanged(nameof(IsSignedIn));
        OnPropertyChanged(nameof(StatusMessage));
        OnPropertyChanged(nameof(DetailMessage));
        OnPropertyChanged(nameof(SignedInAccountName));
        OnPropertyChanged(nameof(ManagerLifecycleState));
    }

    private async Task CompleteCoreAsync(
        PendingAuthChallenge pending,
        string? totpCode,
        CoordinatorOperation operation)
    {
        if (_client is null)
        {
            throw new ServerClientException(
                ServerClientFailure.NotAvailableInThisBuild,
                "Authority trust is not configured for this process.");
        }

        var login = await _client.CompleteChallengeAsync(pending, totpCode, operation.Token)
            .ConfigureAwait(true);

        // Reject an already-expired completion before UI install. The client
        // may have raced its own deadline between reception and this point.
        if (!_client.IsSessionLive)
        {
            _client.ClearSessionIfBearer(login.Token);
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "Session has expired.");
        }

        // Ownership is re-checked at the actual state-install point. Cancel or
        // sign-out between client success and this continuation must not
        // install a signed-in session. Obsolete cleanup may only drop this
        // operation's own bearer — never a replacement session.
        SessionIdentityChangedEventArgs identityChange;
        lock (_gate)
        {
            if (_disposed)
            {
                // Dispose is explicit owner shutdown: full clear is correct.
                _client.ClearSession();
                throw new ObjectDisposedException(nameof(V2SignInCoordinator));
            }

            if (!IsCurrentOperation(operation))
            {
                _client.ClearSessionIfBearer(login.Token);
                throw new ServerClientException(
                    ServerClientFailure.Cancelled,
                    "Sign-in was cancelled before the session could be installed.");
            }

            if (!_client.IsSessionLive)
            {
                _client.ClearSessionIfBearer(login.Token);
                throw new ServerClientException(
                    ServerClientFailure.Unauthorized,
                    "Session has expired.");
            }

            _pending = null;
            var previousGeneration = _installedSessionGeneration;
            _installedSessionGeneration = _client.SessionGeneration;
            unchecked
            {
                _uiEpoch++;
            }

            SignedInAccountName = login.Account?.Username ?? Username;
            ManagerLifecycleState = login.Manager?.LifecycleState ?? "none";
            RequiresTotp = false;
            Phase = V2SignInPhase.SignedIn;
            StatusMessage = $"Signed in as {SignedInAccountName}";
            DetailMessage = DescribeManager(ManagerLifecycleState);
            identityChange = new SessionIdentityChangedEventArgs(previousGeneration, _installedSessionGeneration);
        }

        SessionIdentityChanged?.Invoke(this, identityChange);
    }

    private readonly record struct CoordinatorOperation(int Id, CancellationToken Token);

    private CoordinatorOperation BeginOperation(CancellationTokenSource cts)
    {
        lock (_gate)
        {
            _activeCts = cts;
            _activeOperation++;
            unchecked
            {
                _uiEpoch++;
            }

            return new CoordinatorOperation(_activeOperation, cts.Token);
        }
    }

    private bool IsCurrentOperation(CoordinatorOperation operation)
    {
        lock (_gate)
        {
            return !_disposed && _activeOperation == operation.Id;
        }
    }

    private void EndOperationIfCurrent(CoordinatorOperation operation)
    {
        lock (_gate)
        {
            if (_activeOperation == operation.Id)
            {
                _activeCts = null;
            }
        }
    }

    private void ApplyFailure(ServerClientException ex)
    {
        switch (ex.Failure)
        {
            case ServerClientFailure.Unauthorized:
                Phase = V2SignInPhase.Refused;
                StatusMessage = "Sign-in failed.";
                DetailMessage = "Check the username, password, and authentication code.";
                RequiresTotp = false;
                break;
            case ServerClientFailure.Forbidden:
                Phase = V2SignInPhase.Refused;
                StatusMessage = "Access refused.";
                DetailMessage = DescribeForbidden(ex);
                RequiresTotp = false;
                break;
            case ServerClientFailure.RateLimited:
                Phase = V2SignInPhase.Refused;
                StatusMessage = "Too many sign-in attempts.";
                DetailMessage = "Wait and try again.";
                RequiresTotp = false;
                break;
            case ServerClientFailure.SecurityStateUnavailable:
                Phase = V2SignInPhase.Failed;
                StatusMessage = "Server cannot accept new sign-ins right now.";
                DetailMessage = "Trusted storage is unavailable on the server. Contact your administrator.";
                RequiresTotp = false;
                break;
            case ServerClientFailure.NotAvailableInThisBuild:
                Phase = V2SignInPhase.Unavailable;
                StatusMessage = "Server sign-in is not available in this build.";
                DetailMessage = ex.Message;
                RequiresTotp = false;
                break;
            case ServerClientFailure.Cancelled:
                ResetToReady("Sign-in cancelled.", string.Empty);
                break;
            case ServerClientFailure.Timeout:
            case ServerClientFailure.TransportFailed:
                Phase = V2SignInPhase.Failed;
                StatusMessage = "Could not reach the server.";
                DetailMessage = "Confirm network access and try again.";
                RequiresTotp = false;
                break;
            default:
                Phase = V2SignInPhase.Failed;
                StatusMessage = "Something went wrong.";
                DetailMessage = ex.Message;
                RequiresTotp = false;
                break;
        }
    }

    private void ResetToReady(string status, string detail)
    {
        Phase = V2SignInPhase.Ready;
        StatusMessage = status;
        DetailMessage = detail;
        RequiresTotp = false;
    }

    private void ClearSecrets()
    {
        PendingAuthChallenge? pending;
        lock (_gate)
        {
            pending = _pending;
            _pending = null;
        }

        pending?.Clear();
        _client?.ClearPendingChallenge();
    }

    private void CancelPendingOperation()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            // Invalidate the owning generation so a late continuation cannot
            // install UI state or clear a replacement attempt.
            _activeOperation++;
            cts = _activeCts;
            _activeCts = null;
        }

        try
        {
            cts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already completed.
        }
    }

    private static bool IsSixDigitCode(string? code) =>
        code is { Length: 6 } && code.All(c => c is >= '0' and <= '9');

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
