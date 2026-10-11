using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Helicoid.Domain.Tests;

/// <summary>
/// TEST-ONLY loopback HTTPS server speaking real TLS via SslStream. Used only
/// by Domain.Tests to prove pinned-transport behavior on actual sockets.
/// </summary>
internal sealed class TestHttpsServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly X509Certificate2 _certificate;
    private readonly Func<string, CancellationToken, Task<byte[]>> _responder;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;
    private readonly List<Exception> _errors = new();
    private readonly TaskCompletionSource _tcpAccepted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource? _allowHandshake;
    private int _connectionsServed;

    private TestHttpsServer(
        TcpListener listener,
        X509Certificate2 certificate,
        Func<string, CancellationToken, Task<byte[]>> responder,
        TaskCompletionSource? allowHandshake)
    {
        _listener = listener;
        _certificate = certificate;
        _responder = responder;
        _allowHandshake = allowHandshake;
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }

    /// <summary>Host used in the origin URI (127.0.0.1 or localhost).</summary>
    public string Host { get; init; } = "127.0.0.1";

    public Uri Origin => new($"https://{Host}:{Port}/", UriKind.Absolute);

    public int ConnectionsServed => Volatile.Read(ref _connectionsServed);

    /// <summary>Completes when a TCP client is accepted (before TLS handshake).</summary>
    public Task TcpAccepted => _tcpAccepted.Task;

    public IReadOnlyList<Exception> Errors
    {
        get
        {
            lock (_errors)
            {
                return _errors.ToArray();
            }
        }
    }

    public static TestHttpsServer Start(
        X509Certificate2 serverCertificate,
        Func<string, byte[]> responder,
        string host = "127.0.0.1")
    {
        ArgumentNullException.ThrowIfNull(serverCertificate);
        ArgumentNullException.ThrowIfNull(responder);
        return Start(serverCertificate, (head, _) => Task.FromResult(responder(head)), host);
    }

    public static TestHttpsServer Start(
        X509Certificate2 serverCertificate,
        Func<string, CancellationToken, Task<byte[]>> responder,
        string host = "127.0.0.1")
        => Start(serverCertificate, responder, host, allowHandshake: null);

    /// <summary>
    /// TEST-ONLY: when <paramref name="allowHandshake"/> is provided, the server
    /// signals <see cref="TcpAccepted"/> then waits on that gate before TLS
    /// handshake. Deterministic timing without sleeps.
    /// </summary>
    public static TestHttpsServer Start(
        X509Certificate2 serverCertificate,
        Func<string, CancellationToken, Task<byte[]>> responder,
        string host,
        TaskCompletionSource? allowHandshake)
    {
        ArgumentNullException.ThrowIfNull(serverCertificate);
        ArgumentNullException.ThrowIfNull(responder);

        // Dual-mode IPv6Any accepts both 127.0.0.1 and ::1 so localhost and
        // literal-IP origins reach this listener regardless of resolver order.
        var listener = new TcpListener(IPAddress.IPv6Any, 0);
        listener.Server.DualMode = true;
        listener.Start();
        return new TestHttpsServer(listener, serverCertificate, responder, allowHandshake)
        {
            Host = host,
        };
    }

    private async Task AcceptLoopAsync()
    {
        var token = _cts.Token;
        try
        {
            while (!token.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                _ = Task.Run(() => HandleConnectionAsync(client, token), CancellationToken.None);
            }
        }
        catch (Exception ex)
        {
            RecordError(ex);
        }
    }

    private async Task HandleConnectionAsync(TcpClient client, CancellationToken token)
    {
        try
        {
            using (client)
            {
                client.NoDelay = true;
                _tcpAccepted.TrySetResult();

                if (_allowHandshake is not null)
                {
                    await _allowHandshake.Task.WaitAsync(token).ConfigureAwait(false);
                }

                await using var network = client.GetStream();
                await using var ssl = new SslStream(
                    network,
                    leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: null);
                try
                {
                    await ssl.AuthenticateAsServerAsync(
                        new SslServerAuthenticationOptions
                        {
                            ServerCertificate = _certificate,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                            ClientCertificateRequired = false,
                            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        },
                        token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException)
                {
                    // Client refused the certificate or cancelled the handshake.
                    RecordError(ex);
                    return;
                }

                var head = await ReadRequestHeadAsync(ssl, token).ConfigureAwait(false);
                Interlocked.Increment(ref _connectionsServed);
                var payload = await _responder(head, token).ConfigureAwait(false);
                await ssl.WriteAsync(payload, token).ConfigureAwait(false);
                await ssl.FlushAsync(token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            RecordError(ex);
        }
    }

    private static async Task<string> ReadRequestHeadAsync(Stream stream, CancellationToken token)
    {
        var buffer = new byte[8192];
        var collected = new MemoryStream();
        while (true)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false);
            if (n <= 0)
            {
                break;
            }

            collected.Write(buffer, 0, n);
            var text = Encoding.ASCII.GetString(collected.ToArray());
            var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headerEnd >= 0)
            {
                return text[..(headerEnd + 4)];
            }

            if (collected.Length > 64 * 1024)
            {
                break;
            }
        }

        return Encoding.ASCII.GetString(collected.ToArray());
    }

    private void RecordError(Exception ex)
    {
        lock (_errors)
        {
            _errors.Add(ex);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try
        {
            _listener.Stop();
        }
        catch (SocketException)
        {
        }

        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            RecordError(ex);
        }

        _cts.Dispose();
    }
}
