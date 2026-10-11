using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Helicoid.Domain.Client;

namespace Helicoid.Domain.Tests;

/// <summary>
/// TEST-ONLY bounds for native TLS fixture work. Gates must not await forever.
/// </summary>
internal static class TestTimeouts
{
    /// <summary>Max wait for a server/handshake coordination gate.</summary>
    public static readonly TimeSpan Gate = TimeSpan.FromSeconds(10);

    /// <summary>Upper bound for a single test path (no process hang).</summary>
    public static readonly TimeSpan Test = TimeSpan.FromSeconds(45);

    public static string FormatErrors(IReadOnlyList<Exception> errors)
    {
        if (errors.Count == 0)
        {
            return "(no server errors recorded)";
        }

        var sb = new StringBuilder();
        for (var i = 0; i < errors.Count; i++)
        {
            var ex = errors[i];
            sb.Append('[').Append(i).Append("] ")
                .Append(ex.GetType().Name).Append(": ").Append(ex.Message).AppendLine();
        }

        return sb.ToString();
    }
}

/// <summary>
/// TEST-ONLY: positive-path helpers that surface server handshake exceptions
/// instead of swallowing them behind client EOF/TransportFailed.
/// </summary>
internal static class TlsTestAssert
{
    public static async Task<byte[]> GetOkAsync(
        PinnedHttpsTransport transport,
        TestHttpsServer server,
        string target,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await transport.GetAsync(target, cancellationToken)
                .WaitAsync(TestTimeouts.Test, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new Xunit.Sdk.XunitException(
                $"Positive TLS request '{target}' failed: {ex.GetType().Name}: {ex.Message}\n" +
                $"{ex}\nServer handshake/IO errors:\n{TestTimeouts.FormatErrors(server.Errors)}");
        }
    }

    /// <summary>
    /// Wait for a server gate, but fail fast (with server errors) if the client
    /// request completes first — typically an early TLS/handshake failure.
    /// </summary>
    public static async Task GateOrRequestAsync(
        string gateName,
        Task gate,
        Task request,
        TestHttpsServer server,
        CancellationToken cancellationToken = default)
    {
        var requestTask = request.ContinueWith(
            static t => t,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default).WaitAsync(TestTimeouts.Test, cancellationToken);
        var finished = await Task.WhenAny(gate, requestTask).ConfigureAwait(false);
        if (ReferenceEquals(finished, requestTask))
        {
            var completed = await requestTask.ConfigureAwait(false);
            if (completed.IsFaulted || completed.IsCanceled)
            {
                var ex = completed.Exception?.GetBaseException()
                    ?? new TaskCanceledException(completed);
                throw new Xunit.Sdk.XunitException(
                    $"Client request finished before server gate '{gateName}'.\n{ex}\n" +
                    $"Server handshake/IO errors:\n{TestTimeouts.FormatErrors(server.Errors)}");
            }
        }

        await gate.WaitAsync(TestTimeouts.Gate, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// TEST-ONLY loopback HTTPS server speaking real TLS via SslStream. Used only
/// by Domain.Tests to prove pinned-transport behavior on actual sockets.
/// Listens on IPv4 and IPv6 loopback only (never IPv6Any). Connection handlers
/// are tracked and drained on dispose before the owned leaf is disposed.
/// </summary>
internal sealed class TestHttpsServer : IAsyncDisposable
{
    private readonly List<TcpListener> _listeners = new();
    private readonly X509Certificate2 _certificate;
    private readonly Func<string, CancellationToken, Task<byte[]>> _responder;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _handlers = new();
    private readonly List<Exception> _errors = new();
    private readonly TaskCompletionSource _tcpAccepted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource? _allowHandshake;
    private readonly List<Task> _acceptLoops = new();
    private int _connectionsServed;
    private int _disposed;

    private TestHttpsServer(
        IEnumerable<TcpListener> listeners,
        X509Certificate2 certificate,
        Func<string, CancellationToken, Task<byte[]>> responder,
        TaskCompletionSource? allowHandshake)
    {
        _listeners.AddRange(listeners);
        _certificate = certificate;
        _responder = responder;
        _allowHandshake = allowHandshake;
        Port = ((IPEndPoint)_listeners[0].LocalEndpoint).Port;
        foreach (var listener in _listeners)
        {
            _acceptLoops.Add(Task.Run(() => AcceptLoopAsync(listener)));
        }
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

        // Loopback-only dual stack: 127.0.0.1 and ::1 on one port when possible.
        var listeners = StartLoopbackListeners();
        return new TestHttpsServer(listeners, serverCertificate, responder, allowHandshake)
        {
            Host = host,
        };
    }

    private static List<TcpListener> StartLoopbackListeners()
    {
        var listeners = new List<TcpListener>();
        var v4 = new TcpListener(IPAddress.Loopback, 0);
        v4.Start();
        listeners.Add(v4);
        var port = ((IPEndPoint)v4.LocalEndpoint).Port;

        try
        {
            var v6 = new TcpListener(IPAddress.IPv6Loopback, port);
            v6.Start();
            listeners.Add(v6);
        }
        catch (SocketException)
        {
            // IPv6 loopback unavailable; IPv4 loopback still serves.
        }

        return listeners;
    }

    private async Task AcceptLoopAsync(TcpListener listener)
    {
        var token = _cts.Token;
        try
        {
            while (!token.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
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

                var handler = Task.Run(() => HandleConnectionAsync(client, token), CancellationToken.None);
                lock (_handlers)
                {
                    _handlers.Add(handler);
                }
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
                    // Client refused the certificate, cancelled, or the handshake failed.
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
        catch (Exception ex)
        {
            RecordError(ex);
        }
    }

    private static async Task<string> ReadRequestHeadAsync(Stream stream, CancellationToken token)
    {
        var buffer = new byte[8192];
        using var collected = new MemoryStream();
        while (true)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token)
                .AsTask()
                .WaitAsync(TestTimeouts.Gate, token).ConfigureAwait(false);
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
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _cts.Cancel();
        foreach (var listener in _listeners)
        {
            try
            {
                listener.Stop();
            }
            catch (SocketException)
            {
            }
        }

        foreach (var loop in _acceptLoops)
        {
            try
            {
                await loop.WaitAsync(TestTimeouts.Gate).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                RecordError(ex);
                throw;
            }
        }

        Task[] handlers;
        lock (_handlers)
        {
            handlers = _handlers.ToArray();
        }

        try
        {
            await Task.WhenAll(handlers).WaitAsync(TestTimeouts.Gate).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            RecordError(ex);
            throw;
        }

        // Drain complete: dispose the owned leaf last so in-flight handshakes
        // could not observe a disposed server certificate.
        _certificate.Dispose();
        _cts.Dispose();
    }
}
