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
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _http;
    private string? _bearerToken;

    public DevelopmentServerClient(Uri baseAddress, HttpMessageHandler? handler = null)
    {
        // Same complete address contract for every construction path.
        var canonical = LoopbackAddress.RequireDevelopmentBaseAddress(baseAddress);
        BaseAddress = canonical;

        // disposeHandler:false keeps an injected handler usable by the caller;
        // Dispose() still disposes this HttpClient.
        _http = handler is null
            ? new HttpClient(
                new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    AutomaticDecompression = DecompressionMethods.None,
                    ConnectTimeout = DefaultTimeout,
                },
                disposeHandler: true)
            {
                BaseAddress = canonical,
                Timeout = DefaultTimeout,
            }
            : new HttpClient(handler, disposeHandler: false)
            {
                BaseAddress = canonical,
                Timeout = DefaultTimeout,
            };
    }

    public Uri BaseAddress { get; }

    /// <summary>True after a successful login. The token itself is never exposed.</summary>
    public bool HasSession => _bearerToken is not null;

    public static DevelopmentServerClient CreateLoopback(string? address, HttpMessageHandler? handler = null)
    {
        var uri = LoopbackAddress.RequireLoopbackHttp(address, DefaultPort);
        return new DevelopmentServerClient(uri, handler);
    }

    public async Task<HealthResponse> GetHealthAsync(CancellationToken cancellationToken)
    {
        using var response = await SendAsync(HttpMethod.Get, "/health", authorized: false, body: null, cancellationToken)
            .ConfigureAwait(false);
        var health = await ReadAsync<HealthResponse>(response, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(health.Status) || health.SchemaVersion <= 0)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Health response is missing required fields.");
        }

        return health;
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

        var payload = JsonSerializer.Serialize(
            new LoginRequest
            {
                Username = username,
                Password = password,
                ManagerPublicIdentity = string.IsNullOrWhiteSpace(managerPublicIdentity)
                    ? null
                    : managerPublicIdentity.Trim(),
            },
            JsonOptions);

        try
        {
            using var response = await SendAsync(
                    HttpMethod.Post, "/v1/auth/login", authorized: false,
                    new StringContent(payload, Encoding.UTF8, "application/json"), cancellationToken)
                .ConfigureAwait(false);

            var login = await ReadAsync<LoginResponse>(response, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(login.Token))
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Sign-in succeeded without a session token.");
            }

            if (login.Account is null || string.IsNullOrEmpty(login.Account.Id))
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Sign-in response is missing the account identity.");
            }

            if (login.ExpiresAtUnix <= 0)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "Sign-in response is missing a valid expiry.");
            }

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
        using var response = await SendAsync(HttpMethod.Get, "/v1/auth/session", authorized: true, body: null, cancellationToken)
            .ConfigureAwait(false);
        var session = await ReadAsync<SessionResponse>(response, cancellationToken).ConfigureAwait(false);
        if (session.Account is null || string.IsNullOrEmpty(session.Account.Id))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Session response is missing the account identity.");
        }

        return session;
    }

    public async Task LogoutAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var response = await SendAsync(HttpMethod.Post, "/v1/auth/logout", authorized: true, body: null, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            // Session is cleared even when the server call fails.
            ClearSession();
        }
    }

    public async Task<IReadOnlyList<ComputerRecord>> GetInventoryAsync(CancellationToken cancellationToken)
    {
        using var response = await SendAsync(HttpMethod.Get, "/v1/computers", authorized: true, body: null, cancellationToken)
            .ConfigureAwait(false);
        var payload = await ReadAsync<ComputersResponse>(response, cancellationToken).ConfigureAwait(false);
        return MapInventory(payload);
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

        var list = new List<ComputerRecord>();
        foreach (var computer in payload.Computers)
        {
            if (string.IsNullOrWhiteSpace(computer.Id))
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
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ServerClientException(
                ServerClientFailure.Timeout,
                "The server did not respond in time.");
        }
        catch (OperationCanceledException)
        {
            throw new ServerClientException(
                ServerClientFailure.Cancelled,
                "The request was cancelled.");
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

    private static async Task ThrowForErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var status = (int)response.StatusCode;
        string? code = null;
        string message = "The server rejected the request.";
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var limited = new LimitedReadStream(stream, MaxResponseBytes);
            var envelope = await JsonSerializer.DeserializeAsync<ErrorBody>(limited, JsonOptions, cancellationToken)
                .ConfigureAwait(false);
            code = envelope?.Error?.Code;
            if (!string.IsNullOrWhiteSpace(envelope?.Error?.Message))
            {
                message = envelope!.Error!.Message!;
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or NotSupportedException)
        {
            // Keep the status-based message when the envelope is not JSON.
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
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var limited = new LimitedReadStream(stream, MaxResponseBytes);
        try
        {
            var value = await JsonSerializer.DeserializeAsync<T>(limited, JsonOptions, cancellationToken)
                .ConfigureAwait(false);
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

    /// <summary>Bounds response body reads so oversized payloads fail closed.</summary>
    private sealed class LimitedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _limit;
        private long _read;

        public LimitedReadStream(Stream inner, long limit)
        {
            _inner = inner;
            _limit = limit;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_read >= _limit)
            {
                return ProbeOverflow();
            }

            var allowed = (int)Math.Min(count, _limit - _read);
            var n = _inner.Read(buffer, offset, allowed);
            _read += n;
            return n;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_read >= _limit)
            {
                return ProbeOverflow();
            }

            var allowed = (int)Math.Min(count, _limit - _read);
            var n = await _inner.ReadAsync(buffer.AsMemory(offset, allowed), cancellationToken).ConfigureAwait(false);
            _read += n;
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_read >= _limit)
            {
                return ProbeOverflow();
            }

            var allowed = (int)Math.Min(buffer.Length, _limit - _read);
            var n = await _inner.ReadAsync(buffer[..allowed], cancellationToken).ConfigureAwait(false);
            _read += n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        /// <summary>
        /// At the limit: true EOF is allowed, any further byte means the body
        /// exceeded the bound.
        /// </summary>
        private int ProbeOverflow()
        {
            Span<byte> probe = stackalloc byte[1];
            var n = _inner.Read(probe);
            if (n > 0)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "The server response exceeded the size limit.");
            }

            return 0;
        }
    }
}
