using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Helicoid.Domain.Model;

namespace Helicoid.Domain.Client;

/// <summary>
/// Concrete development client for the loopback HS server HTTP contract v1.
/// Enabled only by an explicit --development-server launch option. Literal
/// loopback HTTP only; redirects are refused. Session tokens live in memory for
/// the process lifetime and are never logged or written to disk.
/// </summary>
public sealed class DevelopmentServerClient : IHsServerClient, IDisposable
{
    public const int DefaultPort = 8787;
    public const int MaxResponseBytes = 256 * 1024;
    public const int ExpectedSchemaVersion = 1;
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _http;
    private readonly TimeSpan _timeout;
    private string? _bearerToken;

    public DevelopmentServerClient(
        Uri baseAddress,
        HttpMessageHandler? handler = null,
        TimeSpan? timeout = null)
    {
        // Same complete address contract for every construction path.
        var canonical = LoopbackAddress.RequireDevelopmentBaseAddress(baseAddress);
        BaseAddress = canonical;
        _timeout = timeout ?? DefaultTimeout;
        if (_timeout <= TimeSpan.Zero)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Timeout must be positive.");
        }

        // disposeHandler:false keeps an injected handler usable by the caller;
        // Dispose() still disposes this HttpClient.
        // HttpClient.Timeout is infinite: the operation-wide deadline below
        // covers headers AND body (ResponseHeadersRead would otherwise only
        // bound headers).
        _http = handler is null
            ? new HttpClient(
                new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    AutomaticDecompression = DecompressionMethods.None,
                    ConnectTimeout = _timeout,
                },
                disposeHandler: true)
            {
                BaseAddress = canonical,
                Timeout = System.Threading.Timeout.InfiniteTimeSpan,
            }
            : new HttpClient(handler, disposeHandler: false)
            {
                BaseAddress = canonical,
                Timeout = System.Threading.Timeout.InfiniteTimeSpan,
            };
    }

    public Uri BaseAddress { get; }

    /// <summary>True after a successful login. The token itself is never exposed.</summary>
    public bool HasSession => _bearerToken is not null;

    public static DevelopmentServerClient CreateLoopback(
        string? address,
        HttpMessageHandler? handler = null,
        TimeSpan? timeout = null)
    {
        var uri = LoopbackAddress.RequireLoopbackHttp(address, DefaultPort);
        return new DevelopmentServerClient(uri, handler, timeout);
    }

    public async Task<HealthResponse> GetHealthAsync(CancellationToken cancellationToken)
    {
        return await WithDeadlineAsync(async ct =>
        {
            using var response = await SendAsync(HttpMethod.Get, "/health", authorized: false, body: null, ct)
                .ConfigureAwait(false);
            var health = await ReadAsync<HealthResponse>(response, ct).ConfigureAwait(false);
            ValidateHealth(health);
            return health;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<LoginResponse> LoginAsync(
        string username,
        string password,
        string? managerPublicIdentity,
        CancellationToken cancellationToken)
    {
        // Never leave a previous bearer alive across a sign-in attempt.
        ClearSession();

        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ServerClientException(ServerClientFailure.BadRequest, "Username is required.");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ServerClientException(ServerClientFailure.BadRequest, "Password is required.");
        }

        var requestedIdentity = string.IsNullOrWhiteSpace(managerPublicIdentity)
            ? null
            : managerPublicIdentity.Trim();

        var payload = JsonSerializer.Serialize(
            new LoginRequest
            {
                Username = username,
                Password = password,
                ManagerPublicIdentity = requestedIdentity,
            },
            JsonOptions);

        try
        {
            var login = await WithDeadlineAsync(async ct =>
            {
                using var response = await SendAsync(
                        HttpMethod.Post, "/v1/auth/login", authorized: false,
                        new StringContent(payload, Encoding.UTF8, "application/json"), ct)
                    .ConfigureAwait(false);

                var parsed = await ReadAsync<LoginResponse>(response, ct).ConfigureAwait(false);
                ValidateLogin(parsed, requestedIdentity);
                return parsed;
            }, cancellationToken).ConfigureAwait(false);

            // Hold the opaque bearer in memory only. Never log or persist it.
            _bearerToken = login.Token;
            return login;
        }
        catch
        {
            ClearSession();
            throw;
        }
    }

    public async Task<SessionResponse> GetSessionAsync(CancellationToken cancellationToken)
    {
        return await WithDeadlineAsync(async ct =>
        {
            using var response = await SendAsync(HttpMethod.Get, "/v1/auth/session", authorized: true, body: null, ct)
                .ConfigureAwait(false);
            var session = await ReadAsync<SessionResponse>(response, ct).ConfigureAwait(false);

            if (session.Account is null)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Session response is missing the account.");
            }

            ValidateAccount(session.Account);
            if (!IsFutureUnix(session.ExpiresAtUnix))
            {
                // Expired session: drop the bearer so no further call reuses it.
                ClearSession();
                throw new ServerClientException(
                    ServerClientFailure.Unauthorized,
                    "Session has expired.");
            }

            return session;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task LogoutAsync(CancellationToken cancellationToken)
    {
        try
        {
            await WithDeadlineAsync(async ct =>
            {
                using var response = await SendAsync(HttpMethod.Post, "/v1/auth/logout", authorized: true, body: null, ct)
                    .ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Session is cleared even when the server call fails.
            ClearSession();
        }
    }

    public async Task<IReadOnlyList<ComputerRecord>> GetInventoryAsync(CancellationToken cancellationToken)
    {
        return await WithDeadlineAsync(async ct =>
        {
            using var response = await SendAsync(HttpMethod.Get, "/v1/computers", authorized: true, body: null, ct)
                .ConfigureAwait(false);
            var payload = await ReadAsync<ComputersResponse>(response, ct).ConfigureAwait(false);
            return MapInventory(payload);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ComputerId>> GetAuthorizedComputerIdsAsync(CancellationToken cancellationToken)
    {
        var inventory = await GetInventoryAsync(cancellationToken).ConfigureAwait(false);
        return inventory.Select(c => c.Id).ToList();
    }

    /// <summary>
    /// Map contract inventory to honest display status. This foundation server
    /// reports no live endpoint presence or frames, so enrolled computers are
    /// shown Offline and pending/quarantined/revoked keep their named state.
    /// Malformed required fields are rejected rather than turned into empty inventory.
    /// </summary>
    public static IReadOnlyList<ComputerRecord> MapInventory(ComputersResponse payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (payload.Computers is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Inventory response is missing the computers list.");
        }

        if (payload.Computers.Count > 100)
        {
            throw new ServerClientException(ServerClientFailure.InvalidResponse,
                "Inventory response exceeded the computer limit.");
        }

        var list = new List<ComputerRecord>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var computer in payload.Computers)
        {
            if (computer is null || string.IsNullOrWhiteSpace(computer.Id)
                || computer.Id.Length > 128 || computer.Id.Any(char.IsControl)
                || !ids.Add(computer.Id))
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Inventory response contains a computer without an id.");
            }

            if (string.IsNullOrWhiteSpace(computer.EnrollmentState))
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Inventory response contains a computer without enrollment state.");
            }

            var status = computer.EnrollmentState switch
            {
                "enrolled" => ComputerStatus.Offline,
                "pending" => ComputerStatus.PendingApproval,
                "quarantined" => ComputerStatus.NeedsAttention,
                "revoked" => ComputerStatus.Unavailable,
                _ => ComputerStatus.Unknown,
            };

            list.Add(new ComputerRecord(
                ComputerId.Parse(computer.Id),
                string.IsNullOrWhiteSpace(computer.FriendlyName) ? computer.Id : computer.FriendlyName,
                status,
                TrustedUserName: null));
        }

        return list;
    }

    public void ClearSession()
    {
        _bearerToken = null;
    }

    public void Dispose()
    {
        ClearSession();
        // disposeHandler:false preserves an injected handler for the caller.
        _http.Dispose();
    }

    private static void ValidateHealth(HealthResponse health)
    {
        if (health.Status is not ("ok" or "degraded")
            || (health.Status == "degraded" && health.AcceptingAuthorizedOperations))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Health response is missing status.");
        }

        if (health.SchemaVersion != ExpectedSchemaVersion)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Health response has an unsupported schema version.");
        }

        if (health.Features is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Health response is missing feature flags.");
        }

        // Required foundation features must be present for this client.
        foreach (var required in new[] { "local_accounts", "manager_enrollment", "scoped_inventory" })
        {
            if (!health.Features.ContainsKey(required))
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Health response is missing required feature flags.");
            }
        }
    }

    private static void ValidateLogin(LoginResponse login, string? requestedManagerIdentity)
    {
        if (string.IsNullOrEmpty(login.Token))
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

        ValidateMfa(login.Mfa);
        ValidateManagerIdentity(login.Manager, requestedManagerIdentity);
    }

    private static void ValidateAccount(AccountDto account)
    {
        if (string.IsNullOrWhiteSpace(account.Id))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Account is missing its id.");
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

    private static void ValidateMfa(MfaDto? mfa)
    {
        if (mfa is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response is missing MFA state.");
        }

        // This foundation does not implement MFA factors. Required+unavailable
        // would mean the client cannot complete sign-in; do not claim MFA works.
        if (mfa.Required)
        {
            throw new ServerClientException(
                ServerClientFailure.NotAvailableInThisBuild,
                "Multi-factor authentication is required but not available in this build.");
        }
    }

    private static void ValidateManagerIdentity(ManagerDto? manager, string? requestedIdentity)
    {
        if (requestedIdentity is null)
        {
            // No manager binding requested: null manager is allowed.
            return;
        }

        if (manager is null)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Sign-in response is missing the requested manager binding.");
        }

        if (string.IsNullOrWhiteSpace(manager.LifecycleState))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Manager binding is missing its lifecycle state.");
        }

        if (!string.Equals(manager.LifecycleState, "approved", StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.Forbidden,
                "Manager is not approved.");
        }

        if (!string.Equals(manager.PublicIdentity, requestedIdentity, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Manager identity does not match the requested manager.");
        }
    }

    private static bool IsFutureUnix(long unixSeconds)
    {
        if (unixSeconds <= 0)
        {
            return false;
        }

        return unixSeconds <= DateTimeOffset.MaxValue.ToUnixTimeSeconds()
            && unixSeconds > DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    /// <summary>
    /// Runs one HTTP operation under a single deadline covering headers and
    /// body. User cancellation stays distinct from timeout.
    /// </summary>
    private async Task<T> WithDeadlineAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken userToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(userToken);
        deadline.CancelAfter(_timeout);
        try
        {
            return await operation(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (userToken.IsCancellationRequested)
        {
            throw new ServerClientException(
                ServerClientFailure.Cancelled,
                "The request was cancelled.");
        }
        catch (OperationCanceledException)
        {
            throw new ServerClientException(
                ServerClientFailure.Timeout,
                "The server did not respond in time.");
        }
    }

    private async Task WithDeadlineAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken userToken)
    {
        await WithDeadlineAsync(async ct =>
        {
            await operation(ct).ConfigureAwait(false);
            return true;
        }, userToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        bool authorized,
        HttpContent? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = body;
        }

        if (authorized)
        {
            if (_bearerToken is null)
            {
                throw new ServerClientException(
                    ServerClientFailure.NotConnected,
                    "No active session. Sign in first.");
            }

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _bearerToken);
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new ServerClientException(
                ServerClientFailure.TransportFailed,
                "Could not reach the development server.",
                ex);
        }

        if (IsRedirect(response.StatusCode))
        {
            response.Dispose();
            throw new ServerClientException(
                ServerClientFailure.RedirectRefused,
                "Redirect responses are refused for the development server.");
        }

        if (!response.IsSuccessStatusCode)
        {
            await ThrowForErrorAsync(response, cancellationToken).ConfigureAwait(false);
        }

        return response;
    }

    private static bool IsRedirect(HttpStatusCode status) =>
        (int)status is >= 300 and < 400;

    private static async Task ThrowForErrorAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var status = (int)response.StatusCode;
        string? code = null;
        string message = "The server rejected the request.";
        try
        {
            var body = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
            try
            {
                var envelope = JsonSerializer.Deserialize<ErrorBody>(body, JsonOptions);
                code = envelope?.Error?.Code;
                if (!string.IsNullOrWhiteSpace(envelope?.Error?.Message))
                {
                    message = envelope!.Error!.Message!;
                }
            }
            catch (JsonException)
            {
                // Keep the status-based message when the envelope is not JSON.
            }
        }
        catch (ServerClientException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        finally
        {
            response.Dispose();
        }

        var failure = MapFailure(status, code);
        throw new ServerClientException(failure, message)
        {
            ErrorCode = code,
            HttpStatus = status,
        };
    }

    private static ServerClientFailure MapFailure(int status, string? code) => code switch
    {
        "unauthorized" => ServerClientFailure.Unauthorized,
        "forbidden" => ServerClientFailure.Forbidden,
        "rate_limited" => ServerClientFailure.RateLimited,
        "security_state_unavailable" => ServerClientFailure.SecurityStateUnavailable,
        "not_found" => ServerClientFailure.NotFound,
        "conflict" => ServerClientFailure.Conflict,
        "bad_request" => ServerClientFailure.BadRequest,
        "not_implemented" => ServerClientFailure.NotAvailableInThisBuild,
        "unprocessable" => ServerClientFailure.BadRequest,
        "internal" => ServerClientFailure.ServerError,
        _ => status switch
        {
            401 => ServerClientFailure.Unauthorized,
            403 => ServerClientFailure.Forbidden,
            404 => ServerClientFailure.NotFound,
            409 => ServerClientFailure.Conflict,
            400 or 422 => ServerClientFailure.BadRequest,
            429 => ServerClientFailure.RateLimited,
            501 => ServerClientFailure.NotAvailableInThisBuild,
            503 => ServerClientFailure.SecurityStateUnavailable,
            _ => ServerClientFailure.ServerError,
        },
    };

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
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

    /// <summary>
    /// Reads the entire body under the size bound so overflow is detected even
    /// after a complete JSON value. EOF at exactly the limit is allowed.
    /// </summary>
    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var buffer = new MemoryStream();
        var chunk = new byte[8192];
        long total = 0;
        while (true)
        {
            var n = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                break;
            }

            total += n;
            if (total > MaxResponseBytes)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "The server response exceeded the size limit.");
            }

            buffer.Write(chunk, 0, n);
        }

        return buffer.ToArray();
    }
}
