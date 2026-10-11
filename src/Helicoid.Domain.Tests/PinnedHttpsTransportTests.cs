using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Real TLS socket proofs for the pinned HTTPS transport. Each test speaks
/// genuine TLS via SslStream against disposable CertificateRequest-generated
/// CA/leaf material. Mac runs prove .NET-on-Mac TLS behavior only; native
/// Windows OS verification is deferred to existing CI.
/// </summary>
public class PinnedHttpsTransportTests
{
    private static DeploymentTlsTrust TrustFor(
        TestDeploymentPki pki,
        Uri origin,
        string? fingerprintOverride = null) =>
        DeploymentTlsTrust.Create(
            "dep-tls-1",
            origin,
            pki.CaDer,
            fingerprintOverride ?? pki.CaFingerprintSha256Hex);

    private static async Task<byte[]> GetAsync(
        PinnedHttpsTransport transport,
        string target,
        CancellationToken cancellationToken = default) =>
        await transport.GetAsync(target, cancellationToken);

    [Fact]
    public async Task Positive_PinnedCa_RealTlsSocket_ReturnsBody()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Json("{\"status\":\"ok\"}"));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var body = await TlsTestAssert.GetOkAsync(transport, server, "/health");

        Assert.Equal("{\"status\":\"ok\"}", Encoding.UTF8.GetString(body));
        Assert.True(server.ConnectionsServed >= 1);
    }

    [Fact]
    public async Task Positive_DnsNameLocalhost_RealTlsSocket()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: "localhost", ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("dns-ok"),
            host: "localhost");

        // Origin host is localhost so TargetHost checks the DNS SAN.
        // Listener is loopback-only dual stack (127.0.0.1 + ::1).
        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var body = await TlsTestAssert.GetOkAsync(transport, server, "/health");
        Assert.Equal("dns-ok", Encoding.UTF8.GetString(body));
    }

    [Fact]
    public async Task ForeignCa_IsRefused_EvenWhenChainIsCryptographicallyValid()
    {
        using var pinnedPki = TestDeploymentPki.Create("HS Pinned CA");
        using var foreignPki = TestDeploymentPki.Create("HS Foreign CA");
        await using var server = TestHttpsServer.Start(
            foreignPki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("should-not-be-trusted"));

        // The foreign chain is valid when that CA is the custom root — so a
        // platform-trusted equivalent would otherwise be acceptable.
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(foreignPki.Ca);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            using var foreignLeaf = foreignPki.CreateLeaf(
                dnsName: null,
                ipAddress: IPAddress.Loopback);
            Assert.True(chain.Build(foreignLeaf), "foreign chain should be crypto-valid under its own CA.");
        }

        var trust = TrustFor(pinnedPki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/health"));
        Assert.Equal(ServerClientFailure.TransportFailed, ex.Failure);
    }

    [Fact]
    public async Task WrongDnsName_IsRefused()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: "wrong.example", ipAddress: null),
            _ => TestHttpScripts.Text("name-mismatch"));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/health"));
        Assert.Equal(ServerClientFailure.TransportFailed, ex.Failure);
    }

    [Fact]
    public async Task ExpiredLeaf_IsRefused()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(
                dnsName: null,
                ipAddress: IPAddress.Loopback,
                notBefore: DateTimeOffset.UtcNow.AddDays(-30),
                notAfter: DateTimeOffset.UtcNow.AddDays(-1)),
            _ => TestHttpScripts.Text("expired"));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/health"));
        Assert.Equal(ServerClientFailure.TransportFailed, ex.Failure);
    }

    [Fact]
    public async Task NonServerAuthLeaf_IsRefused()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(
                dnsName: null,
                ipAddress: IPAddress.Loopback,
                includeServerAuthEku: false,
                includeClientAuthEku: true),
            _ => TestHttpScripts.Text("no-server-auth"));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/health"));
        Assert.Equal(ServerClientFailure.TransportFailed, ex.Failure);
    }

    [Fact]
    public async Task BadPin_IsRefusedAtConstruction()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("unused"));

        var wrongPin = new string('a', DeploymentTlsTrust.Sha256HexLength);
        var ex = Assert.Throws<DeploymentTlsTrustException>(() =>
            TrustFor(pki, server.Origin, fingerprintOverride: wrongPin));
        Assert.Equal(DeploymentTlsTrustFailure.FingerprintMismatch, ex.Failure);
    }

    [Fact]
    public async Task HttpsOriginMismatch_IsRefusedBeforeConnect()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("ok"));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var foreign = Assert.Throws<DeploymentTlsTrustException>(() =>
            trust.ResolveRequestTarget("https://evil.example:443/health"));
        Assert.Equal(DeploymentTlsTrustFailure.OriginMismatch, foreign.Failure);

        var ex = await Assert.ThrowsAsync<DeploymentTlsTrustException>(() =>
            GetAsync(transport, "https://evil.example:443/health"));
        Assert.Equal(DeploymentTlsTrustFailure.OriginMismatch, ex.Failure);
        Assert.Equal(0, server.ConnectionsServed);
    }

    [Fact]
    public async Task Redirects_AreNeverFollowed()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Redirect("https://evil.example/escape", status: 302));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/redirect"));
        Assert.Equal(ServerClientFailure.RedirectRefused, ex.Failure);
    }

    [Fact]
    public async Task SameOriginRedirects_AreAlsoRefused()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            head => TestHttpScripts.Redirect(serverOriginPath(head), status: 307));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/login"));
        Assert.Equal(ServerClientFailure.RedirectRefused, ex.Failure);
        Assert.Equal(1, server.ConnectionsServed);
    }

    private static string serverOriginPath(string requestHead)
    {
        // Keep the redirect on-origin so only the no-follow rule is under test.
        var line = requestHead.Split("\r\n", StringSplitOptions.None)[0];
        var parts = line.Split(' ');
        return parts.Length >= 2 ? parts[1] : "/fallback";
    }

    [Fact]
    public async Task Non2xx_IsRefused()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("nope", status: 500));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/fail"));
        Assert.Equal(ServerClientFailure.ServerError, ex.Failure);
        Assert.Equal(500, ex.HttpStatus);
    }

    [Fact]
    public async Task UnknownAuthChallenge_IsRefused()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.AuthChallenge());

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/secure"));
        Assert.Equal(ServerClientFailure.Unauthorized, ex.Failure);
    }

    [Fact]
    public async Task OversizedBody_IsRefusedAtDefaultBound()
    {
        using var pki = TestDeploymentPki.Create();
        var oversized = new byte[PinnedHttpsTransport.DefaultMaxBodyBytes + 1];
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Raw(200, "application/octet-stream", oversized));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/big"));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task BodyAtExactlyDefaultBound_IsAccepted()
    {
        using var pki = TestDeploymentPki.Create();
        var exact = new byte[PinnedHttpsTransport.DefaultMaxBodyBytes];
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Raw(200, "application/octet-stream", exact));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var body = await TlsTestAssert.GetOkAsync(transport, server, "/exact");
        Assert.Equal(PinnedHttpsTransport.DefaultMaxBodyBytes, body.Length);
    }

    [Fact]
    public async Task ChunkedBody_ExceedingBound_IsRefused()
    {
        using var pki = TestDeploymentPki.Create();
        // 8 KiB chunks * 16 = 128 KiB > 64 KiB default bound.
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Chunked(chunkCount: 16, chunkSize: 8 * 1024));

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/chunked"));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public void NegativeOrOversizedBounds_AreRejected()
    {
        using var pki = TestDeploymentPki.Create();
        var trust = TrustFor(pki, new Uri("https://127.0.0.1:9443/"));

        var negativeTimeout = Assert.Throws<ServerClientException>(() =>
            new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(-1)));
        Assert.Equal(ServerClientFailure.InvalidAddress, negativeTimeout.Failure);

        var zeroTimeout = Assert.Throws<ServerClientException>(() =>
            new PinnedHttpsTransport(trust, timeout: TimeSpan.Zero));
        Assert.Equal(ServerClientFailure.InvalidAddress, zeroTimeout.Failure);

        // Huge finite timeout must be refused at construction, not by CancelAfter later.
        var hugeTimeout = Assert.Throws<ServerClientException>(() =>
            new PinnedHttpsTransport(trust, timeout: TimeSpan.FromDays(400)));
        Assert.Equal(ServerClientFailure.InvalidAddress, hugeTimeout.Failure);

        var negativeBody = Assert.Throws<ServerClientException>(() =>
            new PinnedHttpsTransport(trust, maxBodyBytes: -1));
        Assert.Equal(ServerClientFailure.InvalidAddress, negativeBody.Failure);

        // Zero body cap is not a positive bound.
        var zeroBody = Assert.Throws<ServerClientException>(() =>
            new PinnedHttpsTransport(trust, maxBodyBytes: 0));
        Assert.Equal(ServerClientFailure.InvalidAddress, zeroBody.Failure);

        var overCap = Assert.Throws<ServerClientException>(() =>
            new PinnedHttpsTransport(trust, maxBodyBytes: PinnedHttpsTransport.AbsoluteMaxBodyBytes + 1));
        Assert.Equal(ServerClientFailure.InvalidAddress, overCap.Failure);
    }

    [Fact]
    public void MaxTimeout_BoundaryIsAcceptedAtConstruction()
    {
        using var pki = TestDeploymentPki.Create();
        var trust = TrustFor(pki, new Uri("https://127.0.0.1:9443/"));
        using var transport = new PinnedHttpsTransport(
            trust,
            timeout: PinnedHttpsTransport.MaxTimeout);
        Assert.Equal(PinnedHttpsTransport.MaxTimeout, transport.Timeout);
    }

    [Fact]
    public async Task Cancellation_IsReportedDistinctFromTimeout()
    {
        using var pki = TestDeploymentPki.Create();
        var inServer = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseResponse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            async (_, ct) =>
            {
                inServer.TrySetResult();
                await releaseResponse.Task.WaitAsync(TestTimeouts.Gate, ct);
                return TestHttpScripts.Text("late");
            });

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));
        using var cts = new CancellationTokenSource();

        var request = GetAsync(transport, "/slow", cts.Token);
        // TLS + request are live; then cancel while the server holds the response.
        await TlsTestAssert.GateOrRequestAsync("inServer", inServer.Task, request, server);
        cts.Cancel();

        var ex = await Assert.ThrowsAsync<ServerClientException>(() => request)
            .WaitAsync(TestTimeouts.Test);
        Assert.Equal(ServerClientFailure.Cancelled, ex.Failure);
        releaseResponse.TrySetResult();
    }

    [Fact]
    public async Task Timeout_IsReportedDistinctFromCancellation()
    {
        using var pki = TestDeploymentPki.Create();
        var inServer = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseResponse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            async (_, ct) =>
            {
                inServer.TrySetResult();
                await releaseResponse.Task.WaitAsync(TestTimeouts.Gate, ct);
                return TestHttpScripts.Text("late");
            });

        var trust = TrustFor(pki, server.Origin);
        // Deadline covers headers+body; handshake must finish well inside this.
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(3));

        var request = GetAsync(transport, "/slow");
        await TlsTestAssert.GateOrRequestAsync("inServer", inServer.Task, request, server);

        var ex = await Assert.ThrowsAsync<ServerClientException>(() => request)
            .WaitAsync(TestTimeouts.Test);
        Assert.Equal(ServerClientFailure.Timeout, ex.Failure);
        releaseResponse.TrySetResult();
    }

    [Fact]
    public async Task Dispose_IsCleanAndFurtherRequestsFail()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("ok"));

        var trust = TrustFor(pki, server.Origin);
        var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));
        var body = await TlsTestAssert.GetOkAsync(transport, server, "/health");
        Assert.Equal("ok", Encoding.UTF8.GetString(body));

        transport.Dispose();
        transport.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            GetAsync(transport, "/health"));
    }

    [Fact]
    public async Task MissingOrUnreadableTlsEndpoint_FailsClosed()
    {
        using var pki = TestDeploymentPki.Create();
        // Plain TCP that never speaks TLS — certificate is absent.
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            _ = Task.Run(async () =>
            {
                try
                {
                    using var client = await listener.AcceptTcpClientAsync(cts.Token);
                    // Abrupt close mid-handshake: no server certificate is offered.
                    client.Close();
                }
                catch
                {
                    // Test server lifetime is bounded by the request.
                }
            }, CancellationToken.None);

            var trust = TrustFor(pki, new Uri($"https://127.0.0.1:{port}/"));
            using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(2));

            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                GetAsync(transport, "/health"));
            Assert.Equal(ServerClientFailure.TransportFailed, ex.Failure);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task DeclaredOversizeContentLength_IsRefusedBeforeBodyRead()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ =>
            {
                // Declare far more than the cap; body is never read past the bound.
                var head =
                    "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: application/octet-stream\r\n" +
                    $"Content-Length: {PinnedHttpsTransport.DefaultMaxBodyBytes + 100}\r\n" +
                    "Connection: close\r\n" +
                    "\r\n";
                var payload = new byte[head.Length + 16];
                System.Text.Encoding.ASCII.GetBytes(head).CopyTo(payload, 0);
                return payload;
            });

        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(transport, "/declared-big"));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task MutatingInputCaDer_AfterCreate_CannotRetargetRealTlsAcceptance()
    {
        using var pki = TestDeploymentPki.Create();
        using var foreignPki = TestDeploymentPki.Create("HS Foreign Mutation CA");
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("pinned-ok"));

        var der = pki.CaDer.ToArray();
        var pin = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
        var trust = DeploymentTlsTrust.Create("dep-tls-1", server.Origin, der, pin);

        // Attacker mutates the caller buffer after validation (byte-level tamper).
        Array.Fill(der, (byte)0xA5);

        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));
        var body = await TlsTestAssert.GetOkAsync(transport, server, "/health");

        // Still accepts only the originally pinned CA's leaf — mutation is inert.
        Assert.Equal("pinned-ok", Encoding.UTF8.GetString(body));

        // Foreign-CA leaf against this transport must still be refused.
        await using var foreignServer = TestHttpsServer.Start(
            foreignPki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("foreign"));
        var foreignOriginTrust = DeploymentTlsTrust.Create(
            "dep-tls-1",
            foreignServer.Origin,
            pki.CaDer,
            pki.CaFingerprintSha256Hex);
        using var foreignTransport = new PinnedHttpsTransport(
            foreignOriginTrust,
            timeout: TimeSpan.FromSeconds(10));
        var refused = await Assert.ThrowsAsync<ServerClientException>(() =>
            GetAsync(foreignTransport, "/health"));
        Assert.Equal(ServerClientFailure.TransportFailed, refused.Failure);
    }

    [Fact]
    public async Task MutatingCopyCaDer_AfterCreate_CannotRetargetRealTlsAcceptance()
    {
        using var pki = TestDeploymentPki.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            _ => TestHttpScripts.Text("copy-safe"));

        var trust = TrustFor(pki, server.Origin);
        var copy = trust.CopyCaDer();
        Array.Clear(copy);

        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));
        var body = await TlsTestAssert.GetOkAsync(transport, server, "/health");
        Assert.Equal("copy-safe", Encoding.UTF8.GetString(body));
    }

    [Fact]
    public async Task Close_RetainsRootAndCts_WhileRegisteredRequestInitializesTls()
    {
        using var pki = TestDeploymentPki.Create();
        var allowHandshake = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseResponse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            async (_, ct) =>
            {
                await releaseResponse.Task.WaitAsync(TestTimeouts.Gate, ct);
                return TestHttpScripts.Text("drained");
            },
            host: "127.0.0.1",
            allowHandshake: allowHandshake);

        var trust = TrustFor(pki, server.Origin);
        var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var requestTask = GetAsync(transport, "/health");

        // Deterministic: TCP accepted; TLS handshake not yet started.
        await TlsTestAssert.GateOrRequestAsync("TcpAccepted", server.TcpAccepted, requestTask, server);
        Assert.True(transport.ActiveRequestCount >= 1);
        Assert.False(transport.IsCloseRequested);
        Assert.False(transport.AreNativeResourcesReleased);

        transport.Dispose();

        Assert.True(transport.IsCloseRequested);
        // Close may complete a fast drain if the request already finished; when a
        // registration is still held, root/CTS must remain alive.
        if (transport.ActiveRequestCount > 0)
        {
            Assert.False(transport.AreNativeResourcesReleased);
        }

        // Registered operation may still initialize/use native TLS with the root.
        allowHandshake.TrySetResult();

        // Request is cancelled by close (or may complete if cancel raced late).
        var outcome = await requestTask.ContinueWith(
            t => t.Exception?.GetBaseException() ?? (t.IsCompletedSuccessfully ? null : new Exception("incomplete")),
            TaskScheduler.Default).WaitAsync(TestTimeouts.Test);

        Assert.True(transport.IsCloseRequested);
        Assert.Equal(0, transport.ActiveRequestCount);
        Assert.True(transport.AreNativeResourcesReleased);

        if (outcome is not null)
        {
            Assert.True(
                outcome is ObjectDisposedException
                || outcome is ServerClientException sc
                    && sc.Failure is ServerClientFailure.Cancelled or ServerClientFailure.Timeout
                        or ServerClientFailure.TransportFailed,
                $"Unexpected outcome: {outcome.GetType().Name}: {outcome.Message}\n" +
                TestTimeouts.FormatErrors(server.Errors));
        }

        releaseResponse.TrySetResult();
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            GetAsync(transport, "/health"));
    }

    [Fact]
    public async Task Dispose_InFlightRequest_IsCancelledSafely_AndNewStartsFail()
    {
        using var pki = TestDeploymentPki.Create();
        var inServer = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseResponse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            async (_, ct) =>
            {
                inServer.TrySetResult();
                await releaseResponse.Task.WaitAsync(TestTimeouts.Gate, ct);
                return TestHttpScripts.Text("late");
            });

        var trust = TrustFor(pki, server.Origin);
        var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var inFlight = GetAsync(transport, "/slow");

        // Deterministic: request completed real TLS and is blocked in the responder.
        await TlsTestAssert.GateOrRequestAsync("inServer", inServer.Task, inFlight, server);

        transport.Dispose();

        Assert.True(transport.IsCloseRequested);
        if (transport.ActiveRequestCount > 0)
        {
            Assert.False(transport.AreNativeResourcesReleased);
        }

        var inFlightEx = await Assert.ThrowsAnyAsync<Exception>(() => inFlight)
            .WaitAsync(TestTimeouts.Test);
        Assert.True(
            inFlightEx is ObjectDisposedException
            || (inFlightEx is ServerClientException sc
                && sc.Failure is ServerClientFailure.Cancelled or ServerClientFailure.Timeout
                    or ServerClientFailure.TransportFailed),
            $"Unexpected in-flight dispose outcome: {inFlightEx.GetType().Name}: {inFlightEx.Message}\n" +
            TestTimeouts.FormatErrors(server.Errors));

        Assert.Equal(0, transport.ActiveRequestCount);
        Assert.True(transport.AreNativeResourcesReleased);

        var startEx = await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            GetAsync(transport, "/health"));
        Assert.IsType<ObjectDisposedException>(startEx);

        releaseResponse.TrySetResult();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public async Task Dispose_DuringConcurrentStarts_KeepsCertificateLifetimeSafe(int iteration)
    {
        _ = iteration;
        using var pki = TestDeploymentPki.Create();
        var releaseResponse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            async (_, ct) =>
            {
                await releaseResponse.Task.WaitAsync(TestTimeouts.Gate, ct);
                return TestHttpScripts.Text("ok");
            });

        var trust = TrustFor(pki, server.Origin);
        var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(5));

        var startGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var starts = new List<Task>();
        for (var i = 0; i < 8; i++)
        {
            starts.Add(Task.Run(async () =>
            {
                await startGate.Task.WaitAsync(TestTimeouts.Gate);
                try
                {
                    await GetAsync(transport, "/health");
                }
                catch (ObjectDisposedException)
                {
                }
                catch (ServerClientException)
                {
                }
            }));
        }

        startGate.TrySetResult();
        transport.Dispose();
        await Task.WhenAll(starts).WaitAsync(TestTimeouts.Test);

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            GetAsync(transport, "/health"));

        Assert.Equal(0, transport.ActiveRequestCount);
        Assert.True(transport.AreNativeResourcesReleased);

        releaseResponse.TrySetResult();
    }

    [Fact]
    public async Task Close_ThenDrain_ReleasesNativeResourcesExactlyOnce()
    {
        using var pki = TestDeploymentPki.Create();
        var inServer = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseResponse = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            async (_, ct) =>
            {
                inServer.TrySetResult();
                await releaseResponse.Task.WaitAsync(TestTimeouts.Gate, ct);
                return TestHttpScripts.Text("ok");
            });

        var trust = TrustFor(pki, server.Origin);
        var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));

        var first = GetAsync(transport, "/a");
        await TlsTestAssert.GateOrRequestAsync("inServer", inServer.Task, first, server);

        transport.Dispose();
        if (transport.ActiveRequestCount > 0)
        {
            Assert.False(transport.AreNativeResourcesReleased);
        }

        releaseResponse.TrySetResult();
        await Assert.ThrowsAnyAsync<Exception>(() => first).WaitAsync(TestTimeouts.Test);

        Assert.True(transport.AreNativeResourcesReleased);
        Assert.Equal(0, transport.ActiveRequestCount);

        transport.Dispose();
        Assert.True(transport.AreNativeResourcesReleased);
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            GetAsync(transport, "/b"));
    }

    [Fact]
    public async Task LeafAsAnchor_IsRefusedAtConstruction()
    {
        using var pki = TestDeploymentPki.Create();
        using var leaf = pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback);

        // Leaf-as-anchor is refused at trust construction (BasicConstraints CA=false).
        var ex = Assert.Throws<DeploymentTlsTrustException>(() =>
            DeploymentTlsTrust.Create(
                "dep-tls-1",
                new Uri("https://127.0.0.1:9443/"),
                leaf.RawData,
                Convert.ToHexString(SHA256.HashData(leaf.RawData))
                    .ToLowerInvariant()));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidCaCertificate, ex.Failure);

        // Positive control: a CA-signed leaf is accepted under the pinned CA.
        await using var server = TestHttpsServer.Start(
            leaf,
            _ => TestHttpScripts.Text("leaf-serve"));
        var trust = TrustFor(pki, server.Origin);
        using var transport = new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10));
        var body = await TlsTestAssert.GetOkAsync(transport, server, "/health");
        Assert.Equal("leaf-serve", Encoding.UTF8.GetString(body));
    }
}
