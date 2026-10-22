using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Helicoid.Domain.Client;

/// <summary>
/// Bounded, cancelable HTTPS transport pinned to one deployment CA and origin.
/// Native SocketsHttpHandler TLS with X509ChainPolicy custom-root trust only;
/// no OS/browser root fallback, no redirect following, no cookies/credentials/
/// proxy/cache adoption. This is transport trust, not account authentication.
///
/// Lifecycle: each admitted request holds a registration that keeps the pinned
/// root, CTS, and handler alive until its finally releases the registration.
/// Dispose marks closed atomically, requests cancellation, and frees native
/// resources exactly once only after active registrations have drained.
/// </summary>
public sealed class PinnedHttpsTransport : IDisposable
{
    /// <summary>Default decoded body cap (64 KiB).</summary>
    public const int DefaultMaxBodyBytes = 64 * 1024;

    /// <summary>Absolute body cap that cannot be raised (1 MiB).</summary>
    public const int AbsoluteMaxBodyBytes = 1024 * 1024;

    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Largest deadline CancellationTokenSource.CancelAfter accepts
    /// (Int32.MaxValue milliseconds). Larger finite timeouts are refused at
    /// construction instead of throwing later.
    /// </summary>
    public static readonly TimeSpan MaxTimeout = TimeSpan.FromMilliseconds(int.MaxValue);

    // Lifecycle states (single owner of CTS Cancel; single winner of release).
    private const int LifecycleOpen = 0;
    private const int LifecycleCloseRequested = 1;
    private const int LifecycleCancelCompleted = 2;
    private const int LifecycleReleased = 3;

    private readonly DeploymentTlsTrust _trust;
    private readonly HttpClient _http;
    private readonly X509Certificate2 _caCertificate;
    private readonly CancellationTokenSource _disposeCts;
    private readonly TimeSpan _timeout;
    private readonly int _maxBodyBytes;

    private int _lifecycle;
    private int _activeRegistrations;

    public PinnedHttpsTransport(
        DeploymentTlsTrust trust,
        TimeSpan? timeout = null,
        int maxBodyBytes = DefaultMaxBodyBytes)
    {
        ArgumentNullException.ThrowIfNull(trust);
        _trust = trust;

        _timeout = timeout ?? DefaultTimeout;
        if (!IsValidTimeout(_timeout))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Timeout must be a positive duration within the supported deadline range.");
        }

        if (maxBodyBytes <= 0 || maxBodyBytes > AbsoluteMaxBodyBytes)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Body size bound must be positive and within the absolute hard cap.");
        }

        _maxBodyBytes = maxBodyBytes;
        _caCertificate = trust.CreateCaCertificate();
        _disposeCts = new CancellationTokenSource();

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = _timeout,
            UseCookies = false,
            UseProxy = false,
            Credentials = null,
            DefaultProxyCredentials = null,
            PreAuthenticate = false,
            SslOptions = CreateSslOptions(_caCertificate, trust.Origin.Host),
        };

        // Timeout is infinite: the per-operation deadline covers headers AND body.
        _http = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = trust.Origin,
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        };
    }

    public DeploymentTlsTrust Trust => _trust;

    public Uri Origin => _trust.Origin;

    public TimeSpan Timeout => _timeout;

    public int MaxBodyBytes => _maxBodyBytes;

    /// <summary>True once Dispose has requested close (new starts denied).</summary>
    public bool IsCloseRequested => Volatile.Read(ref _lifecycle) >= LifecycleCloseRequested;

    /// <summary>True once native root/CTS/handler resources were freed.</summary>
    public bool AreNativeResourcesReleased => Volatile.Read(ref _lifecycle) >= LifecycleReleased;

    /// <summary>Admitted requests that have not yet released their registration.</summary>
    public int ActiveRequestCount => Math.Max(0, Volatile.Read(ref _activeRegistrations));

    /// <summary>
    /// GET a same-origin path and return the bounded body bytes.
    /// </summary>
    public Task<byte[]> GetAsync(string requestTarget, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Get, requestTarget, content: null, cancellationToken);

    /// <summary>
    /// Bounded cancelable HTTPS request seam. Per-operation deadline covers
    /// connection, headers, and body. Redirects and non-2xx responses fail.
    /// An optional bearer token is attached as Authorization only; it is never
    /// placed on the request target and never logged. An optional expected
    /// status further narrows which successful response is accepted.
    /// </summary>
    public async Task<byte[]> SendAsync(
        HttpMethod method,
        string requestTarget,
        HttpContent? content,
        CancellationToken cancellationToken,
        string? bearerToken = null,
        int? expectedStatusCode = null)
    {
        ArgumentNullException.ThrowIfNull(method);

        // Validate before registration: no native resources touched on this path.
        var target = _trust.ResolveRequestTarget(requestTarget);

        if (!TryRegister())
        {
            throw new ObjectDisposedException(nameof(PinnedHttpsTransport));
        }

        try
        {
            return await WithDeadlineAsync(async ct =>
            {
                using var request = new HttpRequestMessage(method, target);
                if (content is not null)
                {
                    request.Content = content;
                }

                if (!string.IsNullOrEmpty(bearerToken))
                {
                    request.Headers.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);
                }

                HttpResponseMessage response;
                try
                {
                    response = await _http.SendAsync(
                        request,
                        HttpCompletionOption.ResponseHeadersRead,
                        ct).ConfigureAwait(false);
                }
                catch (HttpRequestException ex) when (IsTlsFailure(ex))
                {
                    throw new ServerClientException(
                        ServerClientFailure.TransportFailed,
                        "TLS trust validation failed for the deployment origin.",
                        ex);
                }
                catch (HttpRequestException ex)
                {
                    throw new ServerClientException(
                        ServerClientFailure.TransportFailed,
                        "Could not reach the deployment origin.",
                        ex);
                }

                using (response)
                {
                    if (IsRedirect(response.StatusCode))
                    {
                        throw new ServerClientException(
                            ServerClientFailure.RedirectRefused,
                            "Redirect responses are refused for the deployment transport.");
                    }

                    if (IsAuthChallenge(response))
                    {
                        throw new ServerClientException(
                            ServerClientFailure.Unauthorized,
                            "Authentication challenges are refused for the deployment transport.");
                    }

                    if (!response.IsSuccessStatusCode ||
                        (expectedStatusCode is int expected && (int)response.StatusCode != expected))
                    {
                        var status = (int)response.StatusCode;
                        throw new ServerClientException(
                            response.IsSuccessStatusCode ? ServerClientFailure.InvalidResponse : MapStatus(status),
                            response.IsSuccessStatusCode
                                ? "The deployment origin returned an unexpected success status."
                                : "The deployment origin rejected the request.")
                        {
                            HttpStatus = status,
                        };
                    }

                    // Refuse a declared oversize before any body bytes are read.
                    if (response.Content.Headers.ContentLength is long declared
                        && declared > _maxBodyBytes)
                    {
                        throw new ServerClientException(
                            ServerClientFailure.InvalidResponse,
                            "The deployment origin response exceeded the size limit.")
                        {
                            HttpStatus = (int)response.StatusCode,
                        };
                    }

                    return await ReadBoundedAsync(response, ct).ConfigureAwait(false);
                }
            }, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Every admission path (success, error, cancel, dispose) releases.
            Unregister();
        }
    }

    /// <summary>
    /// Marks closed and requests cancellation. May return before in-flight
    /// requests finish; the last registration release performs drain cleanup
    /// and frees native resources exactly once.
    /// </summary>
    public void Dispose()
    {
        RequestClose();
    }

    /// <summary>
    /// Native client TLS: TLS 1.2+, chain anchored solely in the pinned CA
    /// (custom root trust), no AIA/CA downloads, no user-installed root
    /// fallback, server-auth EKU, valid dates. Hostname is checked by SslStream
    /// against the request host; name mismatch is never accepted. No remote
    /// certificate validation callback is installed.
    /// </summary>
    internal static SslClientAuthenticationOptions CreateSslOptions(
        X509Certificate2 pinnedCa,
        string targetHost)
    {
        var chainPolicy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            DisableCertificateDownloads = true,
            RevocationMode = X509RevocationMode.NoCheck,
            RevocationFlag = X509RevocationFlag.ExcludeRoot,
            VerificationFlags = X509VerificationFlags.NoFlag,
            UrlRetrievalTimeout = TimeSpan.Zero,
        };
        chainPolicy.CustomTrustStore.Add(pinnedCa);
        // Server authentication EKU must hold on the leaf.
        chainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));

        return new SslClientAuthenticationOptions
        {
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            CertificateChainPolicy = chainPolicy,
            TargetHost = targetHost,
        };
    }

    /// <summary>
    /// Admission barrier. True when the caller must hold a registration until
    /// <see cref="Unregister"/>. Atomic after-close denial: a registration that
    /// races close is withdrawn and may perform drain cleanup.
    /// </summary>
    private bool TryRegister()
    {
        while (true)
        {
            if (Volatile.Read(ref _lifecycle) >= LifecycleCloseRequested)
            {
                return false;
            }

            Interlocked.Increment(ref _activeRegistrations);

            // Publish-then-check: if close raced in, withdraw the registration.
            if (Volatile.Read(ref _lifecycle) >= LifecycleCloseRequested)
            {
                if (Interlocked.Decrement(ref _activeRegistrations) == 0)
                {
                    TryReleaseNativeResources();
                }

                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Releases one admission. Must run on every admitted path. When this is
    /// the last registration and close was requested, performs drain cleanup.
    /// </summary>
    private void Unregister()
    {
        if (Interlocked.Decrement(ref _activeRegistrations) == 0)
        {
            TryReleaseNativeResources();
        }
    }

    /// <summary>
    /// Close: deny new starts, run the single owner cancel (outside any lock),
    /// then release if already drained. Dispose may return before in-flight
    /// work finishes; drain cleanup runs when the last registration leaves.
    /// </summary>
    private void RequestClose()
    {
        if (Interlocked.CompareExchange(ref _lifecycle, LifecycleCloseRequested, LifecycleOpen)
            == LifecycleOpen)
        {
            // Sole owner of CTS.Cancel. No lifecycle lock is held across Cancel
            // (cancellation callbacks must not observe a held lock).
            try
            {
                _disposeCts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Already released; cancellation is a no-op.
            }

            // Publish cancel completion before any Dispose of the CTS so a
            // concurrent TryReleaseNativeResources cannot free it mid-Cancel.
            Interlocked.CompareExchange(
                ref _lifecycle,
                LifecycleCancelCompleted,
                LifecycleCloseRequested);
        }

        TryReleaseNativeResources();
    }

    /// <summary>
    /// Frees native root/CTS/handler exactly once, and only after close has
    /// completed cancellation AND active registrations have drained, so that
    /// no admitted request can still initialize or use native TLS.
    /// </summary>
    private void TryReleaseNativeResources()
    {
        // Drain barrier: a registered operation may still use the root/CTS.
        if (Volatile.Read(ref _activeRegistrations) != 0)
        {
            return;
        }

        var lifecycle = Volatile.Read(ref _lifecycle);
        if (lifecycle < LifecycleCancelCompleted)
        {
            // Close has not finished cancellation yet; RequestClose will retry
            // after Cancel returns, or a later Unregister will observe
            // LifecycleCancelCompleted.
            return;
        }

        if (Interlocked.CompareExchange(
                ref _lifecycle,
                LifecycleReleased,
                LifecycleCancelCompleted)
            != LifecycleCancelCompleted)
        {
            return;
        }

        // Single winner of 2→3. Cancel already completed and active == 0.
        _http.Dispose();
        _caCertificate.Dispose();
        _disposeCts.Dispose();
    }

    /// <summary>
    /// Lifecycle token for admitted requests only. Retrieval happens while the
    /// registration is held, so the CTS cannot be disposed underneath Token.
    /// </summary>
    private CancellationToken LifecycleToken()
    {
        // Registration guarantees the CTS is alive. Do not call after Unregister.
        return _disposeCts.Token;
    }

    private static bool IsValidTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
        {
            return false;
        }

        // CancelAfter throws if the span exceeds Int32.MaxValue milliseconds.
        if (timeout > MaxTimeout)
        {
            return false;
        }

        var seconds = timeout.TotalSeconds;
        return !double.IsNaN(seconds) && !double.IsInfinity(seconds);
    }

    private async Task<T> WithDeadlineAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken userToken)
    {
        // Capture the lifecycle token while this request is registered.
        var lifecycleToken = LifecycleToken();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(
            userToken,
            lifecycleToken);
        deadline.CancelAfter(_timeout);
        try
        {
            return await operation(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (IsCloseRequested)
        {
            throw new ObjectDisposedException(nameof(PinnedHttpsTransport));
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
                "The deployment origin did not respond in time.");
        }
    }

    private async Task<byte[]> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        long total = 0;
        while (true)
        {
            var n = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken)
                .ConfigureAwait(false);
            if (n == 0)
            {
                break;
            }

            total += n;
            if (total > _maxBodyBytes)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "The deployment origin response exceeded the size limit.")
                {
                    HttpStatus = (int)response.StatusCode,
                };
            }

            buffer.Write(chunk, 0, n);
        }

        return buffer.ToArray();
    }

    private static bool IsRedirect(HttpStatusCode status) =>
        (int)status is >= 300 and < 400;

    private static bool IsAuthChallenge(HttpResponseMessage response)
    {
        var status = (int)response.StatusCode;
        if (status is not (401 or 407))
        {
            return false;
        }

        return response.Headers.WwwAuthenticate.Count > 0
            || response.Headers.ProxyAuthenticate.Count > 0;
    }

    private static ServerClientFailure MapStatus(int status) => status switch
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
    };

    private static bool IsTlsFailure(HttpRequestException ex)
    {
        for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
        {
            if (inner is AuthenticationException)
            {
                return true;
            }

            if (inner is IOException io && io.InnerException is AuthenticationException)
            {
                return true;
            }
        }

        return false;
    }
}
