using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// PREPARATORY-ONLY admission seam tests: one authenticated v2 Manager session
/// requests a one-use grant and consumes only the endpoint's certificate-
/// attested challenge. The authority tuple is supplied in memory because no
/// persisted Manager checkpoint exists yet. No native peer, offer, capture, or
/// input is exercised.
/// </summary>
public sealed class ObservationManagerAdmissionClientTests
{
    private const string TrustedDeployment = "dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string AccountId = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d";
    private const string ManagerId = "7a01cf88-6fdb-4cc1-a72f-d155f5309355";
    private const string ComputerId = "e475b9ca-801a-4f71-b5d5-b87daaaae731";
    private const string OtherComputerId = "00000000-0000-4000-8000-000000000002";
    private const string EndpointSessionId = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1";
    private const string GrantId = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173";
    private const long NowUnix = 1_800_000_000;

    [Fact]
    public async Task RequestGrantAsync_VerifiesSignedGrantAgainstLiveManagerSession()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(serverKey, managerKey, endpointKey);

        await using var server = StartServerWithBody(pki, (head, body) =>
        {
            if (head.StartsWith(
                    "POST /v2/admissions/observation HTTP/1.1\r\n",
                    StringComparison.Ordinal))
            {
                Assert.Contains("Authorization: Bearer tok", head, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("Content-Type: application/json", head, StringComparison.OrdinalIgnoreCase);
                Assert.Equal(
                    $"{{\"computer_id\":\"{ComputerId}\"}}",
                    Encoding.UTF8.GetString(body));
                return TestHttpScripts.Json(GrantResponseJson(token), status: 201);
            }

            return AuthResponse(head, managerKey);
        });

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);

        ObservationManagerAdmission admission = await observation.RequestGrantAsync(
            ComputerId, CancellationToken.None);

        Assert.Equal(GrantId, admission.Grant.GrantId);
        Assert.Equal(TrustedDeployment, admission.Grant.DeploymentId);
        Assert.Equal(AccountId, admission.Grant.AccountId);
        Assert.Equal(ManagerId, admission.Grant.ManagerId);
        Assert.Equal(ComputerId, admission.Grant.ComputerId);
        Assert.Equal(endpointKey.PublicKeyHex, admission.Grant.EndpointPublicKeyHex);
        Assert.Equal(EndpointSessionId, admission.Grant.EndpointSessionId);
        Assert.Equal(3L, admission.Grant.EnrollmentEpoch);
        Assert.Equal(NowUnix + 9, admission.Grant.ExpiresAtUnix);
    }

    [Fact]
    public async Task RequestGrantAsync_RejectsGrantForAnotherComputerOrSigningKey()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var otherServerKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));

        string wrongComputerToken = CreateGrantToken(
            serverKey, managerKey, endpointKey, computerId: OtherComputerId);
        string wrongKeyToken = CreateGrantToken(
            otherServerKey, managerKey, endpointKey);
        var responses = new Queue<byte[]>(new[]
        {
            TestHttpScripts.Json(GrantResponseJson(wrongComputerToken), status: 201),
            TestHttpScripts.Json(GrantResponseJson(wrongKeyToken), status: 201),
        });

        await using var server = StartServer(pki, head =>
            head.Contains("/v2/admissions/observation", StringComparison.Ordinal)
                ? responses.Dequeue()
                : AuthResponse(head, managerKey));

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);

        var wrongComputer = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.RequestGrantAsync(ComputerId, CancellationToken.None));
        Assert.Equal(ServerClientFailure.Unauthorized, wrongComputer.Failure);

        var wrongKey = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.RequestGrantAsync(ComputerId, CancellationToken.None));
        Assert.Equal(ServerClientFailure.Unauthorized, wrongKey.Failure);
    }

    [Fact]
    public async Task RequestGrantAsync_RejectsMalformedOrUnboundResponse()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(serverKey, managerKey, endpointKey);
        string valid = GrantResponseJson(token);

        var responses = new Queue<byte[]>(new[]
        {
            TestHttpScripts.Json(valid.Insert(valid.Length - 1, ",\"extra\":true"), status: 201),
            TestHttpScripts.Json(
                valid.Replace(
                    $"\"expires_at_unix\":{NowUnix + 9}",
                    $"\"expires_at_unix\":{NowUnix + 9}.0",
                    StringComparison.Ordinal),
                status: 201),
            TestHttpScripts.Json(valid, status: 200),
            TestHttpScripts.Json(
                valid.Replace(GrantId, OtherComputerId, StringComparison.Ordinal),
                status: 201),
        });

        await using var server = StartServer(pki, head =>
            head.Contains("/v2/admissions/observation", StringComparison.Ordinal)
                ? responses.Dequeue()
                : AuthResponse(head, managerKey));

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);

        int cases = responses.Count;
        for (int index = 0; index < cases; index++)
        {
            var exception = await Assert.ThrowsAsync<ServerClientException>(() =>
                observation.RequestGrantAsync(ComputerId, CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, exception.Failure);
        }
    }

    [Fact]
    public async Task RequestGrantAsync_AcceptsSignedGrantClockSkewWithinGrantTtl()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        // Server is five seconds ahead. The signed grant is still exactly ten
        // seconds long, and the verifier already permits five seconds of skew.
        string token = CreateGrantToken(
            serverKey,
            managerKey,
            endpointKey,
            issuedAtUnix: NowUnix + 5,
            expiresAtUnix: NowUnix + 15);

        await using var server = StartServer(pki, head =>
            head.Contains("/v2/admissions/observation", StringComparison.Ordinal)
                ? TestHttpScripts.Json(
                    GrantResponseJson(token, expiresAtUnix: NowUnix + 15),
                    status: 201)
                : AuthResponse(head, managerKey));

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);

        ObservationManagerAdmission admission = await observation.RequestGrantAsync(
            ComputerId, CancellationToken.None);

        Assert.Equal(NowUnix + 15, admission.Grant.ExpiresAtUnix);
    }

    [Fact]
    public async Task RequestGrantAsync_RejectsExpiryBeyondSignedTtlAndSkew()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(
            serverKey,
            managerKey,
            endpointKey,
            issuedAtUnix: NowUnix + 6,
            expiresAtUnix: NowUnix + 16);

        await using var server = StartServer(pki, head =>
            head.Contains("/v2/admissions/observation", StringComparison.Ordinal)
                ? TestHttpScripts.Json(
                    GrantResponseJson(token, expiresAtUnix: NowUnix + 16),
                    status: 201)
                : AuthResponse(head, managerKey));

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);

        var exception = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.RequestGrantAsync(ComputerId, CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, exception.Failure);
    }

    [Fact]
    public async Task RequestGrantAsync_RejectsAuthorityCheckpointMismatch()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));

        Assert.Throws<ServerClientException>(() => ObservationAuthorityCheckpoint.Create(
            "dep_short",
            serverKey.PublicKeyHex,
            authorityGeneration: 1));
        Assert.Throws<ServerClientException>(() => ObservationAuthorityCheckpoint.Create(
            TrustedDeployment,
            serverKey.PublicKeyHex,
            authorityGeneration: 0));
        Assert.Throws<ServerClientException>(() => ObservationAuthorityCheckpoint.Create(
            TrustedDeployment,
            "not-a-32-byte-key",
            authorityGeneration: 1));

        var otherDeployment = ObservationAuthorityCheckpoint.Create(
            "dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            serverKey.PublicKeyHex,
            authorityGeneration: 1);

        await using var server = StartServer(pki, head => AuthResponse(head, managerKey));
        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(client, otherDeployment, clock);

        var exception = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.RequestGrantAsync(ComputerId, CancellationToken.None));
        Assert.Equal(ServerClientFailure.Unauthorized, exception.Failure);
    }

    [Fact]
    public async Task RequestGrantAsync_RequiresCurrentSessionAndCanonicalComputer()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        await using var server = StartServer(pki, head => AuthResponse(head, managerKey));
        using var client = NewClient(pki, server, clock, managerKey);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);

        var noSession = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.RequestGrantAsync(ComputerId, CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotConnected, noSession.Failure);

        await SignInAsync(client);
        var malformed = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.RequestGrantAsync("not-a-uuid", CancellationToken.None));
        Assert.Equal(ServerClientFailure.BadRequest, malformed.Failure);
    }

    [Fact]
    public async Task PollChallengeAsync_AcceptsOnlyVerifiedEndpointCertificateChallenge()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(serverKey, managerKey, endpointKey);
        string nonce = CreateNonce("4a");
        byte[] certificate = CreateEndpointCertificate();
        string challenge = CreateChallengePayload(
            token,
            serverKey,
            managerKey,
            endpointKey,
            certificate,
            nonce);
        byte[] batch = SignalBatchJson(
            1,
            (1, "endpoint", "challenge", challenge));

        await using var server = StartServerWithBody(pki, (head, body) =>
        {
            if (head.StartsWith(
                    $"GET /v2/admissions/observation/{GrantId}/signals?after=0 HTTP/1.1\r\n",
                    StringComparison.Ordinal))
            {
                Assert.Contains("Authorization: Bearer tok", head, StringComparison.OrdinalIgnoreCase);
                Assert.Empty(body);
                return TestHttpScripts.Json(Encoding.UTF8.GetString(batch));
            }

            if (head.StartsWith(
                    "POST /v2/admissions/observation HTTP/1.1\r\n",
                    StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(GrantResponseJson(token), status: 201);
            }

            return AuthResponse(head, managerKey);
        });

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);
        ObservationManagerAdmission admission = await observation.RequestGrantAsync(
            ComputerId, CancellationToken.None);

        ObservationChallengePoll poll = await observation.PollChallengeAsync(
            admission, afterCursor: 0, CancellationToken.None);

        Assert.Equal(1L, poll.Cursor);
        Assert.NotNull(poll.Challenge);
        Assert.Equal(ComputerId, poll.Challenge!.ComputerId);
        Assert.Equal(EndpointSessionId, poll.Challenge.EndpointSessionId);
        Assert.Equal(nonce, poll.Challenge.EndpointNonceHex);
        Assert.Equal(NowUnix + 9, poll.Challenge.ExpiresAtUnix);
        Assert.True(certificate.AsSpan().SequenceEqual(poll.Challenge.CopyEndpointCertificatePem()));
    }

    [Fact]
    public async Task PollChallengeAsync_RejectsWrongSignalKindSenderAndSignature()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        using var otherEndpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(serverKey, managerKey, endpointKey);
        string nonce = CreateNonce("4a");
        byte[] certificate = CreateEndpointCertificate();
        string validChallenge = CreateChallengePayload(
            token, serverKey, managerKey, endpointKey, certificate, nonce);
        string wrongSignatureChallenge = CreateChallengePayload(
            token, serverKey, managerKey, otherEndpointKey, certificate, nonce);

        var batches = new Dictionary<long, byte[]>
        {
            [0] = SignalBatchJson(1, (1, "manager", "challenge", validChallenge)),
            [1] = SignalBatchJson(2, (2, "endpoint", "offer", validChallenge)),
            [2] = SignalBatchJson(3, (3, "endpoint", "challenge", wrongSignatureChallenge)),
            [3] = SignalBatchJson(3, (3, "endpoint", "challenge", validChallenge)),
        };

        await using var server = StartServer(pki, head =>
        {
            foreach (var (cursor, body) in batches)
            {
                if (head.Contains($"signals?after={cursor} ", StringComparison.Ordinal))
                {
                    return TestHttpScripts.Json(Encoding.UTF8.GetString(body));
                }
            }

            return head.Contains("/v2/admissions/observation", StringComparison.Ordinal)
                ? TestHttpScripts.Json(GrantResponseJson(token), status: 201)
                : AuthResponse(head, managerKey);
        });

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);
        ObservationManagerAdmission admission = await observation.RequestGrantAsync(
            ComputerId, CancellationToken.None);

        foreach (long after in batches.Keys)
        {
            var exception = await Assert.ThrowsAsync<ServerClientException>(() =>
                observation.PollChallengeAsync(admission, after, CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, exception.Failure);
        }
    }

    [Fact]
    public async Task PollChallengeAsync_PreventsCursorRegressionAndChallengeReplay()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(serverKey, managerKey, endpointKey);
        string nonce = CreateNonce("4a");
        byte[] certificate = CreateEndpointCertificate();
        string challenge = CreateChallengePayload(
            token, serverKey, managerKey, endpointKey, certificate, nonce);
        byte[] emptyBatch = SignalBatchJson(5);
        byte[] challengeBatch = SignalBatchJson(
            6,
            (6, "endpoint", "challenge", challenge));

        await using var server = StartServerWithBody(pki, (head, body) =>
        {
            if (head.StartsWith(
                    $"GET /v2/admissions/observation/{GrantId}/signals?after=0 HTTP/1.1\r\n",
                    StringComparison.Ordinal))
            {
                Assert.Empty(body);
                return TestHttpScripts.Json(Encoding.UTF8.GetString(emptyBatch));
            }

            if (head.StartsWith(
                    $"GET /v2/admissions/observation/{GrantId}/signals?after=5 HTTP/1.1\r\n",
                    StringComparison.Ordinal))
            {
                Assert.Empty(body);
                return TestHttpScripts.Json(Encoding.UTF8.GetString(challengeBatch));
            }

            if (head.StartsWith(
                    "POST /v2/admissions/observation HTTP/1.1\r\n",
                    StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(GrantResponseJson(token), status: 201);
            }

            return AuthResponse(head, managerKey);
        });

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);
        ObservationManagerAdmission admission = await observation.RequestGrantAsync(
            ComputerId, CancellationToken.None);

        ObservationChallengePoll empty = await observation.PollChallengeAsync(
            admission, afterCursor: 0, CancellationToken.None);
        Assert.Equal(5L, empty.Cursor);
        Assert.Null(empty.Challenge);

        var backwards = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.PollChallengeAsync(admission, afterCursor: 4, CancellationToken.None));
        Assert.Equal(ServerClientFailure.BadRequest, backwards.Failure);

        ObservationChallengePoll accepted = await observation.PollChallengeAsync(
            admission, afterCursor: 5, CancellationToken.None);
        Assert.Equal(6L, accepted.Cursor);
        Assert.NotNull(accepted.Challenge);

        var replay = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.PollChallengeAsync(admission, afterCursor: 6, CancellationToken.None));
        Assert.Equal(ServerClientFailure.Unauthorized, replay.Failure);
    }

    [Fact]
    public async Task PollChallengeAsync_RejectsExpiredGrantAndHonoursCancellation()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(serverKey, managerKey, endpointKey);

        await using var server = StartServer(pki, head =>
            head.Contains("/v2/admissions/observation", StringComparison.Ordinal)
                ? TestHttpScripts.Json(GrantResponseJson(token), status: 201)
                : AuthResponse(head, managerKey));

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);
        ObservationManagerAdmission admission = await observation.RequestGrantAsync(
            ComputerId, CancellationToken.None);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var cancelled = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.PollChallengeAsync(admission, afterCursor: 0, cancellation.Token));
        Assert.Equal(ServerClientFailure.Cancelled, cancelled.Failure);

        clock.Advance(TimeSpan.FromSeconds(10));
        var expired = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.PollChallengeAsync(admission, afterCursor: 0, CancellationToken.None));
        Assert.Equal(ServerClientFailure.Unauthorized, expired.Failure);
    }

    [Fact]
    public async Task RequestGrantAsync_HonoursCancellationBeforeAnyRequest()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));

        await using var server = StartServer(pki, head => AuthResponse(head, managerKey));
        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var exception = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.RequestGrantAsync(ComputerId, cancellation.Token));
        Assert.Equal(ServerClientFailure.Cancelled, exception.Failure);
    }

    [Fact]
    public async Task PollChallengeAsync_RejectsGrantAfterSessionEndsOrIsReplaced()
    {
        using var pki = TestDeploymentPki.Create("HS observation admission CA");
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        string token = CreateGrantToken(serverKey, managerKey, endpointKey);

        await using var server = StartServer(pki, head =>
            head.Contains("/v2/admissions/observation", StringComparison.Ordinal)
                ? TestHttpScripts.Json(GrantResponseJson(token), status: 201)
                : AuthResponse(head, managerKey));

        using var client = NewClient(pki, server, clock, managerKey);
        await SignInAsync(client);
        var observation = new ObservationManagerAdmissionClient(
            client, Authority(serverKey), clock);
        ObservationManagerAdmission admission = await observation.RequestGrantAsync(
            ComputerId, CancellationToken.None);

        client.ClearSession();

        var ended = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.PollChallengeAsync(admission, afterCursor: 0, CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotConnected, ended.Failure);

        await SignInAsync(client);
        var replaced = await Assert.ThrowsAsync<ServerClientException>(() =>
            observation.PollChallengeAsync(admission, afterCursor: 0, CancellationToken.None));
        Assert.Equal(ServerClientFailure.Unauthorized, replaced.Failure);
    }

    private static ObservationAuthorityCheckpoint Authority(Ed25519DeviceKey serverKey) =>
        ObservationAuthorityCheckpoint.Create(
            TrustedDeployment,
            serverKey.PublicKeyHex,
            authorityGeneration: 1);

    private static TestHttpsServer StartServer(
        TestDeploymentPki pki,
        Func<string, byte[]> responder) =>
        TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            responder);

    private static TestHttpsServer StartServerWithBody(
        TestDeploymentPki pki,
        Func<string, byte[], byte[]> responder) =>
        TestHttpsServer.StartWithBody(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            responder);

    private static V2DeviceKeyChallengeClient NewClient(
        TestDeploymentPki pki,
        TestHttpsServer server,
        FakeTimeProvider clock,
        Ed25519DeviceKey managerKey)
    {
        var trust = DeploymentTlsTrust.Create(
            TrustedDeployment,
            server.Origin,
            pki.CaDer,
            pki.CaFingerprintSha256Hex);
        return new V2DeviceKeyChallengeClient(
            new PinnedHttpsTransport(trust, timeout: TimeSpan.FromSeconds(10)),
            managerKey,
            TrustedDeployment,
            ownsTransport: true,
            clock);
    }

    private static async Task SignInAsync(V2DeviceKeyChallengeClient client)
    {
        PendingAuthChallenge pending = await client.BeginChallengeAsync(
            "alice", "password", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, totpCode: null, CancellationToken.None);
    }

    private static byte[] AuthResponse(string head, Ed25519DeviceKey managerKey)
    {
        if (head.Contains("/v2/auth/challenge/complete", StringComparison.Ordinal))
        {
            return TestHttpScripts.Json(LoginJson(managerKey), status: 200);
        }

        if (head.Contains("/v2/auth/challenge", StringComparison.Ordinal))
        {
            return TestHttpScripts.Json(BeginJson(managerKey), status: 201);
        }

        throw new Xunit.Sdk.XunitException("Unexpected request: " + head);
    }

    private static string BeginJson(Ed25519DeviceKey managerKey) =>
        FormattableString.Invariant(
            $"{{\"challenge_id\":\"c1\",\"challenge_token\":\"t1\",\"operation\":\"session\",\"manager_public_key\":\"{managerKey.PublicKeyHex}\",\"deployment_id\":\"{TrustedDeployment}\",\"expires_at_unix\":{NowUnix + 90},\"mfa_required\":false}}");

    private static string LoginJson(Ed25519DeviceKey managerKey) =>
        FormattableString.Invariant(
            $"{{\"token\":\"tok\",\"expires_at_unix\":{NowUnix + 3600},\"account\":{{\"id\":\"{AccountId}\",\"username\":\"alice\",\"state\":\"active\",\"capabilities\":{{}},\"revision\":1}},\"manager\":{{\"id\":\"{ManagerId}\",\"public_identity\":\"key:{managerKey.PublicKeyHex}\",\"lifecycle_state\":\"approved\"}},\"mfa\":{{\"required\":false,\"available\":false}},\"manager_public_key\":\"{managerKey.PublicKeyHex}\"}}");

    private static string CreateGrantToken(
        Ed25519DeviceKey serverKey,
        Ed25519DeviceKey managerKey,
        Ed25519DeviceKey endpointKey,
        string computerId = ComputerId,
        long issuedAtUnix = NowUnix - 1,
        long expiresAtUnix = NowUnix + 9)
    {
        string payload = FormattableString.Invariant(
            $"{{\"version\":1,\"grant_id\":\"{GrantId}\",\"deployment_id\":\"{TrustedDeployment}\",\"account_id\":\"{AccountId}\",\"manager_id\":\"{ManagerId}\",\"manager_public_key\":\"{managerKey.PublicKeyHex}\",\"computer_id\":\"{computerId}\",\"endpoint_public_key\":\"{endpointKey.PublicKeyHex}\",\"endpoint_session_id\":\"{EndpointSessionId}\",\"enrollment_epoch\":3,\"issued_at_unix\":{issuedAtUnix},\"expires_at_unix\":{expiresAtUnix},\"capability\":\"observe\"}}");
        byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
        byte[] domain = Encoding.UTF8.GetBytes("hs-observation-grant-v1\0");
        byte[] signedMessage = new byte[domain.Length + payloadBytes.Length];
        domain.CopyTo(signedMessage, 0);
        payloadBytes.CopyTo(signedMessage, domain.Length);
        byte[] signature = serverKey.Sign(signedMessage);
        try
        {
            return Convert.ToBase64String(payloadBytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_') + "." + Ed25519DeviceKey.ToLowerHex(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payloadBytes);
            CryptographicOperations.ZeroMemory(signedMessage);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static string GrantResponseJson(string token, long? expiresAtUnix = null) =>
        FormattableString.Invariant(
            $"{{\"grant_id\":\"{GrantId}\",\"computer_id\":\"{ComputerId}\",\"expires_at_unix\":{expiresAtUnix ?? NowUnix + 9},\"grant_token\":\"{token}\"}}");

    private static string CreateChallengePayload(
        string grantToken,
        Ed25519DeviceKey serverKey,
        Ed25519DeviceKey managerKey,
        Ed25519DeviceKey signingEndpointKey,
        byte[] certificatePem,
        string nonce)
    {
        VerifiedObservationAdmissionGrant grant =
            ObservationAdmissionGrantVerifier.VerifyForManager(
                grantToken,
                serverKey.PublicKeyHex,
                new ObservationAdmissionManager(
                    TrustedDeployment,
                    AccountId,
                    ComputerId,
                    ManagerId,
                    managerKey.PublicKeyHex),
                DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        byte[] message = grant.CreatePeerCertificateAttestationMessage(
            certificatePem,
            nonce,
            ObservationPeerRole.Endpoint,
            NowUnix);
        byte[] signature = signingEndpointKey.Sign(message);
        try
        {
            return JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["computer_id"] = ComputerId,
                ["endpoint_session_id"] = EndpointSessionId,
                ["endpoint_nonce"] = nonce,
                ["expires_at_unix"] = NowUnix + 9,
                ["endpoint_certificate_pem"] = Encoding.UTF8.GetString(certificatePem),
                ["endpoint_certificate_signature"] = Ed25519DeviceKey.ToLowerHex(signature),
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static string CreateNonce(string pair) =>
        string.Concat(Enumerable.Repeat(pair, 32));

    private static byte[] CreateEndpointCertificate() =>
        Encoding.UTF8.GetBytes(
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n");

    private static byte[] SignalBatchJson(
        long cursor,
        params (long Sequence, string Sender, string Kind, string Payload)[] messages)
    {
        var wireMessages = messages.Select(message => new Dictionary<string, object>
        {
            ["sequence"] = message.Sequence,
            ["sender"] = message.Sender,
            ["kind"] = message.Kind,
            ["payload"] = message.Payload,
        }).ToArray();
        return JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["cursor"] = cursor,
            ["messages"] = wireMessages,
        });
    }
}
