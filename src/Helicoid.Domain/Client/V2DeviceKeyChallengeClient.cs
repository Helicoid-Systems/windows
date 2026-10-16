using System.Globalization;
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
    private readonly object _gate = new();

    private PendingAuthChallenge? _pending;
    private string? _bearerToken;
    private long _sessionExpiresAtUnix;
    private bool _disposed;

    /// <summary>
    /// Monotonic begin/install generation. A late, cancelled, or failed begin
    /// may only clear or replace pending state while it is still the current
    /// generation; newer pending state is never erased by an obsolete reply.
    /// </summary>
    private int _beginGeneration;

    public V2DeviceKeyChallengeClient(
        DeploymentTlsTrust trust,
        Ed25519DeviceKey deviceKey,
        TimeSpan? timeout = null)
        : this(new PinnedHttpsTransport(trust, timeout), deviceKey, trust.DeploymentId, ownsTransport: true)
    {
    }

    /// <summary>
    /// Test/injection seam. <paramref name="trustedDeploymentId"/> is the
    /// independently enrolled authority deployment identity and must match
    /// the transport trust DeploymentId. Never take this value from
    /// network-discovered health or an untrusted response.
    /// </summary>
    internal V2DeviceKeyChallengeClient(
        PinnedHttpsTransport transport,
        Ed25519DeviceKey deviceKey,
        string trustedDeploymentId,
        bool ownsTransport)
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
    }

    public Ed25519DeviceKey DeviceKey { get; }

    /// <summary>True after a successful challenge completion. Token never exposed.</summary>
    public bool HasSession
    {
        get
        {
            lock (_gate)
            {
                return _bearerToken is not null;
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
        }

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

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
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
            // Fresh reception timestamp: a 7200s server TTL issued just before
            // the response arrives must not be measured against a pre-await
            // clock. Strict upper bound is still applied to remaining lifetime.
            var receptionUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            ValidateCompletedLogin(login, pending, receptionUnixSeconds);

            // Hold bearer in process memory only.
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

                _bearerToken = login.Token;
                _sessionExpiresAtUnix = login.ExpiresAtUnix;
                _pending = null;
            }

            pending.Clear();
            return login;
        }
        catch
        {
            // A failed or cancelled completion never leaves a session installed
            // for this attempt. A newer pending challenge is left untouched.
            lock (_gate)
            {
                if (ReferenceEquals(_pending, pending))
                {
                    _bearerToken = null;
                    _sessionExpiresAtUnix = 0;
                }
            }

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

    /// <summary>Drop any in-memory pending challenge and session.</summary>
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

    /// <summary>Drop any in-memory bearer session. Never persists tokens.</summary>
    public void ClearSession()
    {
        lock (_gate)
        {
            _bearerToken = null;
            _sessionExpiresAtUnix = 0;
        }
    }

    /// <summary>
    /// Clear the bearer only when it is still the exact token this operation
    /// installed. A replacement session is never erased by obsolete cleanup.
    /// </summary>
    public void ClearSessionIfBearer(string? bearerToken)
    {
        if (string.IsNullOrEmpty(bearerToken))
        {
            return;
        }

        lock (_gate)
        {
            if (string.Equals(_bearerToken, bearerToken, StringComparison.Ordinal))
            {
                _bearerToken = null;
                _sessionExpiresAtUnix = 0;
            }
        }
    }

    public async Task<SessionResponse> GetSessionAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var body = await SendJsonAsync(
                HttpMethod.Get,
                "/v1/auth/session",
                payload: null,
                authorized: true,
                cancellationToken)
            .ConfigureAwait(false);

        var session = ParseJson<SessionResponse>(body);
        if (session.Account is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Session response is missing the account.");
        }

        if (!IsFutureUnix(session.ExpiresAtUnix))
        {
            ClearSession();
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "Session has expired.");
        }

        return session;
    }

    public async Task LogoutAsync(CancellationToken cancellationToken)
    {
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
            ClearSession();
            ClearPendingChallenge();
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
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        ClearPendingChallenge();
        ClearSession();
        if (_ownsTransport)
        {
            _transport.Dispose();
        }
    }

    private static bool IsSixDigitCode(string? code) =>
        code is { Length: 6 }
        && code.All(c => c is >= '0' and <= '9');

    private static bool IsFutureUnix(long unixSeconds) =>
        unixSeconds > 0
        && unixSeconds <= DateTimeOffset.MaxValue.ToUnixTimeSeconds()
        && unixSeconds > DateTimeOffset.UtcNow.ToUnixTimeSeconds();

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

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
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

        if (!IsFutureUnix(login.ExpiresAtUnix))
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
        lock (_gate)
        {
            bearer = _bearerToken;
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

        try
        {
            return await _transport.SendAsync(
                    method,
                    path,
                    content,
                    cancellationToken,
                    bearerToken: authorized ? bearer : null)
                .ConfigureAwait(false);
        }
        catch (ServerClientException ex) when (authorized && ex.Failure is ServerClientFailure.Unauthorized)
        {
            ClearSession();
            throw;
        }
    }
}
