using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Helicoid.Domain.Client;

/// <summary>
/// Native pinned-HTTPS v2 device-key challenge sign-in client.
/// Uses the existing <see cref="PinnedHttpsTransport"/> for independent TLS
/// trust, cancellation, and drain. Production sign-in never falls back to
/// v1/password-only/development labels. When authority trust is absent the
/// caller keeps explicit unavailability instead of constructing this client.
/// </summary>
public sealed class V2DeviceKeyChallengeClient : IDisposable
{
    public const int DefaultMaxBodyBytes = 64 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly PinnedHttpsTransport _transport;
    private readonly bool _ownsTransport;
    private readonly string _trustedDeploymentId;
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();

    private PendingAuthChallenge? _pending;
    private string? _bearerToken;
    private long _sessionExpiresAtUnix;
    private long _sessionDeadlineTimestamp;
    private int _sessionGeneration;
    private ITimer? _sessionTimer;
    private bool _disposed;

    /// <summary>
    /// Monotonic begin/install generation. A late, cancelled, or failed begin
    /// may only clear or replace pending state while it is still the current
    /// generation; newer pending state is never erased by an obsolete reply.
    /// </summary>
    private int _beginGeneration;

    /// <summary>
    /// Raised outside locks when a bounded session deadline (or a matching
    /// authorized 401) invalidates the exact installed generation. Carries the
    /// expired generation so listeners can ignore stale notifications. Never
    /// carries bearer material.
    /// </summary>
    public event EventHandler<SessionExpiredEventArgs>? SessionExpired;

    /// <summary>Generation of the currently installed session, or 0 when none.</summary>
    public int SessionGeneration
    {
        get
        {
            lock (_gate)
            {
                return _bearerToken is null ? 0 : _sessionGeneration;
            }
        }
    }

    public V2DeviceKeyChallengeClient(
        DeploymentTlsTrust trust,
        Ed25519DeviceKey deviceKey,
        TimeSpan? timeout = null)
        : this(
            new PinnedHttpsTransport(trust, timeout),
            deviceKey,
            trust.DeploymentId,
            ownsTransport: true,
            TimeProvider.System)
    {
    }

    /// <summary>
    /// Test/injection seam. <paramref name="trustedDeploymentId"/> is the
    /// independently enrolled authority deployment identity and must match
    /// the transport trust DeploymentId. Never take this value from
    /// network-discovered health or an untrusted response.
    /// <paramref name="timeProvider"/> is an internal deterministic test seam;
    /// production construction selects <see cref="TimeProvider.System"/>.
    /// </summary>
    internal V2DeviceKeyChallengeClient(
        PinnedHttpsTransport transport,
        Ed25519DeviceKey deviceKey,
        string trustedDeploymentId,
        bool ownsTransport,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(deviceKey);
        if (string.IsNullOrWhiteSpace(trustedDeploymentId))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Independently trusted deployment identity is required.");
        }

        if (!string.Equals(trustedDeploymentId, transport.Trust.DeploymentId, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Trusted deployment identity does not match the pinned TLS trust.");
        }

        _transport = transport;
        _ownsTransport = ownsTransport;
        DeviceKey = deviceKey;
        _trustedDeploymentId = trustedDeploymentId;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Ed25519DeviceKey DeviceKey { get; }

    /// <summary>
    /// True only while a validated session is installed and its bounded
    /// deadline has not passed. Enforces expiry even when the deadline timer
    /// is late. Token never exposed.
    /// </summary>
    public bool HasSession
    {
        get
        {
            if (TryExpireDueSession(out var expiredGeneration))
            {
                RaiseSessionExpired(expiredGeneration);
            }

            lock (_gate)
            {
                return _bearerToken is not null;
            }
        }
    }

    /// <summary>True when a live session is installed and not yet expired. No event.</summary>
    public bool IsSessionLive
    {
        get
        {
            lock (_gate)
            {
                return _bearerToken is not null && !IsSessionExpiredLocked();
            }
        }
    }

    public Uri Origin => _transport.Origin;

    /// <summary>
    /// Begin a bounded one-use challenge bound to this deployment, the exact
    /// persistent manager key, and operation=service session.
    /// Clears any previous pending challenge and session first.
    /// </summary>
    public async Task<PendingAuthChallenge> BeginChallengeAsync(
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Atomic generation ownership: one lock covers take-over plus clearing
        // the previous pending/session so a stale reply cannot interleave.
        int generation;
        PendingAuthChallenge? previousPending;
        ITimer? previousTimer;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            unchecked
            {
                _beginGeneration++;
            }

            generation = _beginGeneration;
            previousPending = _pending;
            _pending = null;
            _bearerToken = null;
            _sessionExpiresAtUnix = 0;
            _sessionDeadlineTimestamp = 0;
            unchecked
            {
                _sessionGeneration++;
            }

            previousTimer = _sessionTimer;
            _sessionTimer = null;
        }

        previousTimer?.Dispose();
        previousPending?.Clear();
        PendingAuthChallenge? pendingCapture = null;

        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ServerClientException(ServerClientFailure.BadRequest, "Username is required.");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ServerClientException(ServerClientFailure.BadRequest, "Password is required.");
        }

        if (!Ed25519DeviceKey.TryParsePublicKey(DeviceKey.PublicKeyHex, out _))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Device key public identity is not a 32-byte hex value.");
        }

        // Wire request is built and sent; password is not retained on the client.
        var payload = JsonSerializer.Serialize(
            new AuthChallengeBeginRequest
            {
                Username = username,
                Password = password,
                Operation = AuthChallengeBounds.SessionOperation,
                ManagerPublicKey = DeviceKey.PublicKeyHex,
            },
            JsonOptions);

        try
        {
            var body = await SendJsonAsync(
                    HttpMethod.Post,
                    "/v2/auth/challenge",
                    payload,
                    authorized: false,
                    cancellationToken)
                .ConfigureAwait(false);

            var parsed = ParseBeginResponse(body);
            ValidateBeginResponse(parsed, DeviceKey.PublicKeyHex);

            var tokenBytes = Encoding.UTF8.GetBytes(parsed.ChallengeToken);
            var pending = new PendingAuthChallenge(
                parsed.ChallengeId,
                tokenBytes,
                parsed.DeploymentId,
                parsed.Operation,
                parsed.ManagerPublicKey,
                parsed.ExpiresAtUnix,
                mfaRequired: parsed.MfaRequired ?? true);
            pendingCapture = pending;

            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_beginGeneration != generation)
                {
                    // A newer begin owns pending state; discard this reply.
                    pending.Clear();
                    throw new ServerClientException(
                        ServerClientFailure.Cancelled,
                        "Sign-in was cancelled before the challenge could be installed.");
                }

                _pending = pending;
            }

            return pending;
        }
        catch
        {
            // Only the owning generation may clear its pending state, and only
            // while it is still current — never a replacement's pending.
            lock (_gate)
            {
                if (_beginGeneration == generation && ReferenceEquals(_pending, pendingCapture))
                {
                    _pending = null;
                    pendingCapture?.Clear();
                }
            }

            throw;
        }
    }

    /// <summary>
    /// Complete a pending challenge with an Ed25519 proof and optional TOTP.
    /// Required MFA demands a six-digit code. Cancellation/timeout prevents a
    /// late reply from installing a session.
    /// </summary>
    public async Task<LoginResponse> CompleteChallengeAsync(
        PendingAuthChallenge pending,
        string? totpCode,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(pending);

        if (pending.IsCleared)
        {
            throw new ServerClientException(
                ServerClientFailure.BadRequest,
                "The pending challenge was already used or cleared.");
        }

        lock (_gate)
        {
            if (!ReferenceEquals(_pending, pending))
            {
                throw new ServerClientException(
                    ServerClientFailure.BadRequest,
                    "The pending challenge does not belong to this client.");
            }
        }

        var now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (pending.IsExpired(now))
        {
            ClearPendingChallenge();
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The sign-in challenge has expired.");
        }

        if (!AuthChallengeMessage.IsBoundedToken(pending.ChallengeId))
        {
            ClearPendingChallenge();
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "The pending challenge identifier is invalid.");
        }

        if (!string.Equals(pending.ManagerPublicKeyHex, DeviceKey.PublicKeyHex, StringComparison.Ordinal))
        {
            ClearPendingChallenge();
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Device key identity changed since the challenge was created.");
        }

        if (!string.Equals(pending.DeploymentId, _trustedDeploymentId, StringComparison.Ordinal))
        {
            ClearPendingChallenge();
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge deployment identity does not match the trusted deployment.");
        }

        string? normalizedTotp = null;
        if (pending.MfaRequired)
        {
            if (!IsSixDigitCode(totpCode))
            {
                throw new ServerClientException(
                    ServerClientFailure.BadRequest,
                    "A six-digit authentication code is required.");
            }

            normalizedTotp = totpCode;
        }
        else if (!string.IsNullOrEmpty(totpCode))
        {
            // Optional non-enrolled login omits the factor. An unexpected code
            // is refused rather than silently ignored.
            if (!IsSixDigitCode(totpCode))
            {
                throw new ServerClientException(
                    ServerClientFailure.BadRequest,
                    "The authentication code must be six digits.");
            }

            normalizedTotp = totpCode;
        }

        if (!pending.TryCopyChallengeTokenUtf8(out var challengeToken))
        {
            ClearPendingChallenge();
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The sign-in challenge is no longer available.");
        }

        byte[]? signature = null;
        byte[]? canonical = null;
        try
        {
            canonical = AuthChallengeMessage.BuildCanonical(
                pending.DeploymentId,
                pending.ChallengeId,
                pending.Operation,
                pending.ManagerPublicKeyHex);
            signature = DeviceKey.Sign(canonical);
            var signatureHex = Ed25519DeviceKey.ToLowerHex(signature);

            var payload = JsonSerializer.Serialize(
                new AuthChallengeCompleteRequest
                {
                    ChallengeId = pending.ChallengeId,
                    ChallengeToken = challengeToken,
                    ManagerSignature = signatureHex,
                    TotpCode = normalizedTotp,
                },
                JsonOptions);

            var body = await SendJsonAsync(
                    HttpMethod.Post,
                    "/v2/auth/challenge/complete",
                    payload,
                    authorized: false,
                    cancellationToken)
                .ConfigureAwait(false);

            var login = ParseLoginResponse(body);
            // One precise reception sample drives both wall-clock validation and
            // the checked monotonic deadline. Do not round to whole Unix seconds
            // here — the timer due time and enforcement must share one origin.
            var receptionUtc = _timeProvider.GetUtcNow();
            var receptionTimestamp = _timeProvider.GetTimestamp();
            var receptionUnixSeconds = receptionUtc.ToUnixTimeSeconds();
            ValidateCompletedLogin(login, pending, receptionUnixSeconds);
            var (deadlineTimestamp, remaining) = ComputeSessionDeadline(
                login.ExpiresAtUnix,
                receptionUtc,
                receptionTimestamp);

            // Hold bearer in process memory only.
            int installedGeneration;
            string installedBearer;
            ITimer? previousTimer;
            ITimer? deadlineTimer;
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (!ReferenceEquals(_pending, pending))
                {
                    // Identity / pending changed while the request was in flight.
                    throw new ServerClientException(
                        ServerClientFailure.Cancelled,
                        "Sign-in was cancelled before the session could be installed.");
                }

                unchecked
                {
                    _sessionGeneration++;
                }

                installedGeneration = _sessionGeneration;
                installedBearer = login.Token;
                _bearerToken = login.Token;
                _sessionExpiresAtUnix = login.ExpiresAtUnix;
                _sessionDeadlineTimestamp = deadlineTimestamp;
                _pending = null;
                previousTimer = _sessionTimer;
                _sessionTimer = null;
            }

            previousTimer?.Dispose();
            pending.Clear();

            try
            {
                deadlineTimer = CreateSessionDeadlineTimer(installedGeneration, remaining);
            }
            catch
            {
                // Failed timer registration must not leave a live bearer.
                ClearSessionIfBearer(installedBearer);
                throw;
            }

            var armed = false;
            lock (_gate)
            {
                if (_sessionGeneration == installedGeneration && _bearerToken is not null)
                {
                    var previous = _sessionTimer;
                    _sessionTimer = deadlineTimer;
                    armed = TryArmSessionTimer(deadlineTimer, remaining);
                    if (!armed)
                    {
                        _sessionTimer = previous;
                    }
                    else
                    {
                        previous?.Dispose();
                        deadlineTimer = null;
                    }
                }
            }

            if (!armed)
            {
                deadlineTimer?.Dispose();
                ClearSessionIfBearer(installedBearer);
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Session deadline timer could not be scheduled.");
            }

            return login;
        }
        catch
        {
            // A failed or cancelled completion never leaves a session installed
            // for this attempt. A newer pending challenge is left untouched.
            ITimer? failedTimer;
            lock (_gate)
            {
                if (ReferenceEquals(_pending, pending))
                {
                    _bearerToken = null;
                    _sessionExpiresAtUnix = 0;
                    _sessionDeadlineTimestamp = 0;
                    unchecked
                    {
                        _sessionGeneration++;
                    }

                    failedTimer = _sessionTimer;
                    _sessionTimer = null;
                }
                else
                {
                    failedTimer = null;
                }
            }

            failedTimer?.Dispose();

            if (cancellationToken.IsCancellationRequested
                && ReferenceEquals(_pending, pending))
            {
                pending.Clear();
                if (ReferenceEquals(_pending, pending))
                {
                    _pending = null;
                }
            }

            throw;
        }
        finally
        {
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }

            if (canonical is not null)
            {
                CryptographicOperations.ZeroMemory(canonical);
            }

            if (normalizedTotp is not null && normalizedTotp.Length > 0)
            {
                // String contents cannot be zeroed; drop the reference here.
                normalizedTotp = null;
            }
        }
    }

    /// <summary>Drop any in-memory pending challenge.</summary>
    public void ClearPendingChallenge()
    {
        PendingAuthChallenge? pending;
        lock (_gate)
        {
            pending = _pending;
            _pending = null;
        }

        pending?.Clear();
    }

    /// <summary>
    /// Drop the pending challenge only when no newer begin has taken ownership.
    /// An old logout must never erase a replacement's pending material.
    /// </summary>
    private void ClearPendingChallengeIfBeginGeneration(int beginGeneration)
    {
        PendingAuthChallenge? pending;
        lock (_gate)
        {
            if (_beginGeneration != beginGeneration)
            {
                return;
            }

            pending = _pending;
            _pending = null;
        }

        pending?.Clear();
    }

    /// <summary>Drop any in-memory bearer session. Never persists tokens.</summary>
    public void ClearSession()
    {
        ITimer? timer;
        lock (_gate)
        {
            _bearerToken = null;
            _sessionExpiresAtUnix = 0;
            _sessionDeadlineTimestamp = 0;
            unchecked
            {
                _sessionGeneration++;
            }

            timer = _sessionTimer;
            _sessionTimer = null;
        }

        timer?.Dispose();
    }

    /// <summary>
    /// Clear the bearer only when it is still the exact token this operation
    /// installed. A replacement session is never erased by obsolete cleanup.
    /// Returns true when this call dropped the live session.
    /// </summary>
    public bool ClearSessionIfBearer(string? bearerToken)
    {
        if (string.IsNullOrEmpty(bearerToken))
        {
            return false;
        }

        ITimer? timer;
        lock (_gate)
        {
            if (!string.Equals(_bearerToken, bearerToken, StringComparison.Ordinal))
            {
                return false;
            }

            timer = ClearSessionLocked();
        }

        timer?.Dispose();
        return true;
    }

    /// <summary>
    /// Clear only the exact session generation. A replacement installed while
    /// an older call was in flight is never erased.
    /// </summary>
    public bool ClearSessionIfGeneration(int generation)
    {
        if (generation == 0)
        {
            return false;
        }

        ITimer? timer;
        lock (_gate)
        {
            if (_sessionGeneration != generation || _bearerToken is null)
            {
                return false;
            }

            timer = ClearSessionLocked();
        }

        timer?.Dispose();
        return true;
    }

    public async Task<SessionResponse> GetSessionAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string? requestBearer;
        int requestGeneration;
        lock (_gate)
        {
            requestBearer = _bearerToken;
            requestGeneration = _sessionGeneration;
        }

        var body = await SendJsonAsync(
                HttpMethod.Get,
                "/v1/auth/session",
                payload: null,
                authorized: true,
                cancellationToken)
            .ConfigureAwait(false);

        // Fence the parsed reply to the session that issued the request. A
        // replacement installed in flight must not be destroyed by this body.
        var session = ParseJson<SessionResponse>(body);
        if (session.Account is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Session response is missing the account.");
        }

        // A session/inventory reply never renews or extends the installed
        // deadline. An already-expired wall-clock session is dropped only when
        // this reply still names the live request generation.
        if (!IsFutureUnix(session.ExpiresAtUnix))
        {
            if (IsCurrentSession(requestBearer, requestGeneration)
                && ClearSessionIfGeneration(requestGeneration))
            {
                RaiseSessionExpired(requestGeneration);
            }

            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "Session has expired.");
        }

        return session;
    }

    public async Task LogoutAsync(CancellationToken cancellationToken)
    {
        string? requestBearer;
        int requestGeneration;
        int requestBeginGeneration;
        lock (_gate)
        {
            requestBearer = _bearerToken;
            requestGeneration = _sessionGeneration;
            requestBeginGeneration = _beginGeneration;
        }

        try
        {
            await SendJsonAsync(
                    HttpMethod.Post,
                    "/v1/auth/logout",
                    payload: null,
                    authorized: true,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            // Only the exact session that issued logout is dropped; a
            // replacement installed while logout was in flight is kept. A
            // newer pending challenge from a replacement begin is never erased.
            ClearSessionIfGeneration(requestGeneration);
            ClearPendingChallengeIfBeginGeneration(requestBeginGeneration);
        }
    }

    public async Task<IReadOnlyList<Model.ComputerRecord>> GetInventoryAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var body = await SendJsonAsync(
                HttpMethod.Get,
                "/v1/computers",
                payload: null,
                authorized: true,
                cancellationToken)
            .ConfigureAwait(false);

        var payload = ParseJson<ComputersResponse>(body);
        return DevelopmentServerClient.MapInventory(payload);
    }

    public void Dispose()
    {
        ITimer? timer;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _bearerToken = null;
            _sessionExpiresAtUnix = 0;
            _sessionDeadlineTimestamp = 0;
            unchecked
            {
                _sessionGeneration++;
            }

            timer = _sessionTimer;
            _sessionTimer = null;
        }

        timer?.Dispose();
        ClearPendingChallenge();
        if (_ownsTransport)
        {
            _transport.Dispose();
        }
    }

    private static bool IsSixDigitCode(string? code) =>
        code is { Length: 6 }
        && code.All(c => c is >= '0' and <= '9');

    private bool IsFutureUnix(long unixSeconds) =>
        unixSeconds > 0
        && unixSeconds <= DateTimeOffset.MaxValue.ToUnixTimeSeconds()
        && unixSeconds > _timeProvider.GetUtcNow().ToUnixTimeSeconds();

    private AuthChallengeBeginResponse ParseBeginResponse(byte[] body)
    {
        var parsed = ParseJson<AuthChallengeBeginResponse>(body);
        return parsed;
    }

    private static LoginResponse ParseLoginResponse(byte[] body) =>
        ParseJson<LoginResponse>(body);

    private static T ParseJson<T>(byte[] body)
    {
        try
        {
            var value = JsonSerializer.Deserialize<T>(body, JsonOptions);
            return value ?? throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "The server returned an empty response.");
        }
        catch (JsonException ex)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "The server returned an unreadable response.",
                ex);
        }
    }

    private void ValidateBeginResponse(AuthChallengeBeginResponse parsed, string requestedPublicKeyHex)
    {
        if (!AuthChallengeMessage.IsBoundedToken(parsed.ChallengeId))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge response is missing a bounded challenge id.");
        }

        if (!AuthChallengeMessage.IsBoundedToken(parsed.ChallengeToken))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge response is missing a bounded challenge token.");
        }

        if (!string.Equals(parsed.Operation, AuthChallengeBounds.SessionOperation, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge response operation does not match the requested session operation.");
        }

        if (!string.Equals(parsed.ManagerPublicKey, requestedPublicKeyHex, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge response manager key does not match the requested device key.");
        }

        if (!AuthChallengeMessage.IsBoundedToken(parsed.DeploymentId)
            || !string.Equals(parsed.DeploymentId, _trustedDeploymentId, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge response deployment identity does not match the trusted deployment.");
        }

        var now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (parsed.ExpiresAtUnix <= now)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge response expiry is not in the future.");
        }

        var lifetime = parsed.ExpiresAtUnix - now;
        if (lifetime > AuthChallengeBounds.MaxChallengeLifetimeSeconds)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge response expiry exceeds the allowed lifetime.");
        }
    }

    private static void ValidateCompletedLogin(
        LoginResponse login,
        PendingAuthChallenge pending,
        long nowUnixSeconds)
    {
        if (string.IsNullOrEmpty(login.Token) || login.Token.Length > AuthChallengeBounds.MaxIdentifierLength * 4)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response is missing the session token.");
        }

        if (login.Account is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response is missing the account.");
        }

        ValidateAccount(login.Account);

        // Wall-clock expiry is checked against the same reception sample that
        // feeds the monotonic deadline — not a second clock read.
        if (login.ExpiresAtUnix <= nowUnixSeconds)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response expiry is not in the future.");
        }

        var lifetime = login.ExpiresAtUnix - nowUnixSeconds;
        if (lifetime > AuthChallengeBounds.MaxSessionLifetimeSeconds)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response session lifetime exceeds two hours.");
        }

        if (login.Manager is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response is missing the manager binding.");
        }

        if (!AuthChallengeMessage.IsBoundedToken(login.Manager.Id)
            && login.Manager.Id is not null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response manager id is unbounded.");
        }

        if (!string.Equals(login.Manager.LifecycleState, "approved", StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.Forbidden,
                "Manager is not approved.");
        }

        // Contract rev2: bind the server-derived top-level manager_public_key
        // (from the final approved-key transaction) to the actual signer and
        // challenge key. manager.public_identity is a display label
        // (bootstrap uses key:<hex>) and is never cryptographic key authority.
        if (string.IsNullOrWhiteSpace(login.ManagerPublicKey)
            || !Ed25519DeviceKey.TryParsePublicKey(login.ManagerPublicKey, out _))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response is missing the approved manager public key.");
        }

        if (!string.Equals(login.ManagerPublicKey, pending.ManagerPublicKeyHex, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response manager public key does not match the completed challenge signer.");
        }

        // Validate required/available MFA metadata consistent with the
        // completed challenge, not merely block presence. Required MFA with an
        // unavailable factor is incomplete; optional non-enrolled login must
        // not claim a required factor that was never proven here.
        if (login.Mfa is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response is missing MFA state.");
        }

        if (login.Mfa.Required && !login.Mfa.Available)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response reports required MFA without an available factor.");
        }

        // An active available factor implies required under this contract.
        if (login.Mfa.Available && !login.Mfa.Required)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in MFA metadata reports an available factor without requiring it.");
        }

        if (pending.MfaRequired)
        {
            // Challenge demanded a factor code; the completed session must
            // report that required factor as active/available.
            if (!login.Mfa.Required || !login.Mfa.Available)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Sign-in MFA metadata is inconsistent with the required challenge.");
            }
        }
        else
        {
            // Optional no-factor completion cannot truthfully report active
            // factor availability. Server policy may still mark required
            // without available; a claimed available factor was never proven
            // by this client and is refused.
            if (login.Mfa.Available)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Sign-in MFA metadata is inconsistent with the optional challenge.");
            }
        }
    }

    private static void ValidateAccount(AccountDto account)
    {
        if (string.IsNullOrWhiteSpace(account.Id) || account.Id.Length > AuthChallengeBounds.MaxIdentifierLength
            || account.Id.Any(char.IsControl))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Account is missing a bounded id.");
        }

        if (string.IsNullOrWhiteSpace(account.Username))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Account is missing its username.");
        }

        if (!string.Equals(account.State, "active", StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Account is not in the active state.");
        }

        if (account.Capabilities is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Account is missing capabilities.");
        }

        if (account.Revision <= 0)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Account revision must be positive.");
        }
    }

    private async Task<byte[]> SendJsonAsync(
        HttpMethod method,
        string path,
        string? payload,
        bool authorized,
        CancellationToken cancellationToken)
    {
        string? bearer;
        int requestGeneration;

        if (authorized && TryExpireDueSession(out var expiredGeneration))
        {
            RaiseSessionExpired(expiredGeneration);
        }

        lock (_gate)
        {
            bearer = _bearerToken;
            requestGeneration = _sessionGeneration;
        }

        if (authorized && bearer is null)
        {
            throw new ServerClientException(
                ServerClientFailure.NotConnected,
                "No active session. Sign in first.");
        }

        using var content = payload is null
            ? null
            : new StringContent(payload, Encoding.UTF8, "application/json");

        byte[] body;
        try
        {
            body = await _transport.SendAsync(
                    method,
                    path,
                    content,
                    cancellationToken,
                    bearerToken: authorized ? bearer : null)
                .ConfigureAwait(false);
        }
        catch (ServerClientException ex) when (authorized && ex.Failure is ServerClientFailure.Unauthorized)
        {
            // Only the exact request generation may be cleared; a replacement
            // installed while this call was in flight is left intact.
            if (ClearSessionIfGeneration(requestGeneration))
            {
                RaiseSessionExpired(requestGeneration);
            }

            throw;
        }

        // Shared response boundary: a successful authorized body may only leave
        // this seam when the exact request session is still live. Generation
        // token identity is not enough — the lease may have expired while the
        // timer callback was delayed. Expiry is checked against the current
        // monotonic/UTC deadline. Expire only that installed generation and
        // never erase a replacement.
        if (authorized)
        {
            int fenceExpiredGeneration = 0;
            ITimer? fenceTimer = null;
            var reject = false;
            lock (_gate)
            {
                if (_sessionGeneration != requestGeneration
                    || !string.Equals(_bearerToken, bearer, StringComparison.Ordinal))
                {
                    reject = true;
                }
                else if (IsSessionExpiredLocked())
                {
                    // Ownership of the matching timer is returned here and must
                    // be disposed outside the gate, like every other clear path.
                    fenceTimer = ClearSessionLocked();
                    fenceExpiredGeneration = requestGeneration;
                    reject = true;
                }
            }

            fenceTimer?.Dispose();

            if (fenceExpiredGeneration != 0)
            {
                RaiseSessionExpired(fenceExpiredGeneration);
            }

            if (reject)
            {
                throw new ServerClientException(
                    ServerClientFailure.Unauthorized,
                    "The authorized response belongs to a session that is no longer active.");
            }
        }

        return body;
    }

    /// <summary>
    /// Convert the validated completion lifetime into one checked monotonic
    /// deadline and the precise remaining interval for scheduling. Both share
    /// the same reception sample so a timer that fires fractionally early and
    /// the enforcement check cannot disagree.
    /// </summary>
    private (long DeadlineTimestamp, TimeSpan Remaining) ComputeSessionDeadline(
        long expiresAtUnix,
        DateTimeOffset receptionUtc,
        long receptionTimestamp)
    {
        var expiryUtc = DateTimeOffset.FromUnixTimeSeconds(expiresAtUnix);
        var remaining = expiryUtc - receptionUtc;
        if (remaining <= TimeSpan.Zero
            || remaining.TotalSeconds > AuthChallengeBounds.MaxSessionLifetimeSeconds)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response session lifetime is not a bounded future interval.");
        }

        var frequency = _timeProvider.TimestampFrequency;
        if (frequency <= 0)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Time source does not provide a monotonic timestamp frequency.");
        }

        try
        {
            // Keep sub-second precision without long overflow: TimestampFrequency
            // may be 1e9 and a 2h lifetime is well within decimal's range.
            var remainingTicks = (long)((decimal)remaining.Ticks * frequency / TimeSpan.TicksPerSecond);
            if (remainingTicks <= 0)
            {
                // Fractional lifetime collapsed to zero ticks: fail closed
                // rather than installing an already-dead session.
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Sign-in response session lifetime is not a bounded future interval.");
            }

            return (checked(receptionTimestamp + remainingTicks), remaining);
        }
        catch (OverflowException ex)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response session lifetime overflowed the monotonic deadline.",
                ex);
        }
    }

    private static readonly TimeSpan MinTimerGranularity = TimeSpan.FromMilliseconds(1);

    private ITimer CreateSessionDeadlineTimer(int generation, TimeSpan remaining)
    {
        if (remaining < TimeSpan.Zero)
        {
            remaining = TimeSpan.Zero;
        }

        if (remaining < MinTimerGranularity)
        {
            // Minimum granularity avoids busy polling. The authorization
            // deadline itself is unchanged — lazy checks still fail closed.
            remaining = MinTimerGranularity;
        }

        // Weak callback ownership: the timer must not root the client after it
        // is abandoned. Only the generation number crosses the timer boundary.
        var weak = new WeakReference<V2DeviceKeyChallengeClient>(this);

        // Created disabled, then armed after publication so an early callback
        // cannot race ahead of `_sessionTimer` ownership.
        return _timeProvider.CreateTimer(
            state =>
            {
                if (!weak.TryGetTarget(out var client))
                {
                    return;
                }

                client.OnSessionDeadlineTimer((int)state!);
            },
            generation,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan);
    }

    private static bool TryArmSessionTimer(ITimer timer, TimeSpan remaining)
    {
        if (remaining < MinTimerGranularity)
        {
            remaining = MinTimerGranularity;
        }

        return timer.Change(remaining, Timeout.InfiniteTimeSpan);
    }

    /// <summary>
    /// Convert a monotonic timestamp delta into a TimeSpan using wide
    /// arithmetic. Long multiplication overflows at valid 1 GHz frequency with
    /// a one-hour deadline; decimal keeps the exact due interval.
    /// </summary>
    private static TimeSpan MonotonicDeltaToTimeSpan(long timestampDelta, long frequency)
    {
        if (timestampDelta <= 0 || frequency <= 0)
        {
            return TimeSpan.Zero;
        }

        var ticks = (long)((decimal)timestampDelta * TimeSpan.TicksPerSecond / frequency);
        return ticks > 0 ? TimeSpan.FromTicks(ticks) : TimeSpan.Zero;
    }

    private void OnSessionDeadlineTimer(int generation)
    {
        // Detach the fired one-shot so a replacement can take ownership. The
        // old ITimer is already inactive; disposing it is safe and prevents a
        // non-null stale slot from discarding the rearm.
        ITimer? fired;
        lock (_gate)
        {
            if (_sessionGeneration != generation)
            {
                return;
            }

            fired = _sessionTimer;
            _sessionTimer = null;
        }

        fired?.Dispose();

        if (TryExpireGeneration(generation, out var expiredGeneration))
        {
            RaiseSessionExpired(expiredGeneration);
            return;
        }

        // A one-shot timer may fire fractionally early. When the exact
        // generation is still live and not yet expired, rearm once for the
        // remaining monotonic interval — never busy-poll, never extend.
        // Expiration is tracked independently of whether ClearSessionLocked
        // returned a timer: the fired one-shot was already detached, so a
        // dueNow null is not proof the session is still live.
        TimeSpan remaining = TimeSpan.Zero;
        ITimer? dueNow = null;
        var expiredNow = false;
        var canRearm = false;
        lock (_gate)
        {
            if (_sessionGeneration != generation || _bearerToken is null)
            {
                return;
            }

            if (IsSessionExpiredLocked())
            {
                dueNow = ClearSessionLocked();
                expiredNow = true;
            }
            else
            {
                var now = _timeProvider.GetTimestamp();
                var frequency = _timeProvider.TimestampFrequency;
                if (_sessionDeadlineTimestamp <= now || frequency <= 0)
                {
                    dueNow = ClearSessionLocked();
                    expiredNow = true;
                }
                else
                {
                    remaining = MonotonicDeltaToTimeSpan(_sessionDeadlineTimestamp - now, frequency);
                    canRearm = true;
                }
            }
        }

        if (expiredNow)
        {
            dueNow?.Dispose();
            RaiseSessionExpired(generation);
            return;
        }

        if (!canRearm)
        {
            ForceInvalidateGeneration(generation);
            return;
        }

        ITimer? rearm = null;
        try
        {
            rearm = CreateSessionDeadlineTimer(generation, remaining);
        }
        catch
        {
            // Scheduling failure must invalidate automatically; lazy checks
            // alone are not an acceptable substitute for the deadline signal.
            ForceInvalidateGeneration(generation);
            return;
        }

        var armed = false;
        lock (_gate)
        {
            if (_sessionGeneration == generation && _bearerToken is not null && _sessionTimer is null)
            {
                _sessionTimer = rearm;
                armed = TryArmSessionTimer(rearm, remaining);
                if (!armed)
                {
                    _sessionTimer = null;
                }
            }
        }

        if (!armed)
        {
            rearm.Dispose();
            // Lost the race to install the rearm (replacement/dispose) or the
            // timer would not arm. Fail closed for the exact generation.
            ForceInvalidateGeneration(generation);
        }
    }

    private void ForceInvalidateGeneration(int generation)
    {
        ITimer? timer;
        lock (_gate)
        {
            if (_sessionGeneration != generation || _bearerToken is null)
            {
                return;
            }

            timer = ClearSessionLocked();
        }

        timer?.Dispose();
        RaiseSessionExpired(generation);
    }

    private bool TryExpireDueSession(out int expiredGeneration)
    {
        ITimer? timer;
        lock (_gate)
        {
            expiredGeneration = _sessionGeneration;
            if (_bearerToken is null)
            {
                return false;
            }

            if (!IsSessionExpiredLocked())
            {
                return false;
            }

            timer = ClearSessionLocked();
        }

        timer?.Dispose();
        return true;
    }

    private bool TryExpireGeneration(int generation, out int expiredGeneration)
    {
        ITimer? timer;
        lock (_gate)
        {
            expiredGeneration = generation;
            if (_sessionGeneration != generation || _bearerToken is null)
            {
                return false;
            }

            if (!IsSessionExpiredLocked())
            {
                return false;
            }

            timer = ClearSessionLocked();
        }

        timer?.Dispose();
        return true;
    }

    private bool IsCurrentSession(string? bearer, int generation)
    {
        lock (_gate)
        {
            return generation != 0
                && _sessionGeneration == generation
                && string.Equals(_bearerToken, bearer, StringComparison.Ordinal);
        }
    }

    private bool IsSessionExpiredLocked()
    {
        if (_bearerToken is null)
        {
            return false;
        }

        var nowTimestamp = _timeProvider.GetTimestamp();
        if (_sessionDeadlineTimestamp > 0 && nowTimestamp >= _sessionDeadlineTimestamp)
        {
            return true;
        }

        // Full-precision wall clock: a forward jump past contracted expiry fails
        // closed even when the monotonic bound has not yet elapsed.
        var nowUtc = _timeProvider.GetUtcNow();
        return nowUtc >= DateTimeOffset.FromUnixTimeSeconds(_sessionExpiresAtUnix);
    }

    private ITimer? ClearSessionLocked()
    {
        _bearerToken = null;
        _sessionExpiresAtUnix = 0;
        _sessionDeadlineTimestamp = 0;
        unchecked
        {
            _sessionGeneration++;
        }

        var timer = _sessionTimer;
        _sessionTimer = null;
        return timer;
    }

    private void RaiseSessionExpired(int generation)
    {
        // Event is raised outside the session gate so listeners never deadlock.
        SessionExpired?.Invoke(this, new SessionExpiredEventArgs(generation));
    }
}

/// <summary>
/// Identifies the exact session generation a deadline or matching 401
/// invalidated. Never carries bearer material.
/// </summary>
public sealed class SessionExpiredEventArgs : EventArgs
{
    public SessionExpiredEventArgs(int generation)
    {
        Generation = generation;
    }

    public int Generation { get; }
}
