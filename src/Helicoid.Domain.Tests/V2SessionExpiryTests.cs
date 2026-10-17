using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using Helicoid.Domain.Client;
using Helicoid.Manager.ViewModels;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Bounded v2 session-lifetime proofs: monotonic deadline at reception,
/// automatic invalidation of the exact generation, coordinator/ConnectionViewModel
/// reset, and no bearer/request after deadline. Real pinned HTTPS fixtures.
/// </summary>
public class V2SessionExpiryTests
{
    private const string TrustedDeployment = "dep-auth-v2-1";

    private static DeploymentTlsTrust TrustFor(TestDeploymentPki pki, Uri origin) =>
        DeploymentTlsTrust.Create(
            TrustedDeployment,
            origin,
            pki.CaDer,
            pki.CaFingerprintSha256Hex);

    private static long NowPlus(int seconds) => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + seconds;

    private static byte[] BeginJson(
        string challengeId,
        string challengeToken,
        string managerKeyHex,
        long expiresAtUnix,
        bool mfaRequired)
    {
        return Encoding.UTF8.GetBytes(
            "{\"challenge_id\":\"" + challengeId +
            "\",\"challenge_token\":\"" + challengeToken +
            "\",\"operation\":\"session\"" +
            ",\"manager_public_key\":\"" + managerKeyHex +
            "\",\"deployment_id\":\"" + TrustedDeployment +
            "\",\"expires_at_unix\":" + expiresAtUnix +
            ",\"mfa_required\":" + (mfaRequired ? "true" : "false") + "}");
    }

    private static byte[] LoginJson(
        string token,
        long expiresAtUnix,
        string accountUser,
        string managerKeyHex,
        bool mfaRequired = false,
        bool mfaAvailable = false)
    {
        return Encoding.UTF8.GetBytes(
            "{\"token\":\"" + token +
            "\",\"expires_at_unix\":" + expiresAtUnix +
            ",\"account\":{\"id\":\"acct-1\",\"username\":\"" + accountUser +
            "\",\"state\":\"active\",\"capabilities\":{\"inventory\":true},\"revision\":1}" +
            ",\"manager\":{\"id\":\"mgr-1\",\"public_identity\":\"key:" + managerKeyHex +
            "\",\"friendly_name\":\"Device\",\"lifecycle_state\":\"approved\",\"approved_at_unix\":1}" +
            ",\"mfa\":{\"required\":" + (mfaRequired ? "true" : "false") +
            ",\"available\":" + (mfaAvailable ? "true" : "false") + "}" +
            ",\"manager_public_key\":\"" + managerKeyHex + "\"}");
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly List<IDisposable> _owned = new();

        public required TestHttpsServer Server { get; init; }

        public required V2DeviceKeyChallengeClient Client { get; init; }

        public required Ed25519DeviceKey Key { get; init; }

        public required FakeTimeProvider Time { get; init; }

        public V2SignInCoordinator? Coordinator { get; init; }

        public ConnectionViewModel? Connection { get; init; }

        public MainViewModel? Main { get; init; }

        public int CompleteRequests;

        public long ExpiresAtUnix;

        public void Own(IDisposable disposable) => _owned.Add(disposable);

        public async ValueTask DisposeAsync()
        {
            foreach (var d in _owned)
            {
                d.Dispose();
            }

            Main?.Dispose();
            Connection?.Dispose();
            Coordinator?.Dispose();
            Client.Dispose();
            await Server.DisposeAsync();
        }
    }

    private static Harness Start(
        TestDeploymentPki pki,
        FakeTimeProvider time,
        Func<Harness, string, byte[]> responder,
        bool withCoordinator = false,
        bool withConnection = false,
        bool withMain = false)
    {
        Ed25519DeviceKey key = Ed25519DeviceKey.Create();
        Harness? harness = null;
        var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            head => responder(harness!, head));
        var trust = TrustFor(pki, server.Origin);
        var transport = new PinnedHttpsTransport(trust, timeout: null);
        var client = new V2DeviceKeyChallengeClient(
            transport,
            key,
            trust.DeploymentId,
            ownsTransport: true,
            time);
        V2SignInCoordinator? coordinator = withCoordinator ? new V2SignInCoordinator(client) : null;
        ConnectionViewModel? connection = null;
        MainViewModel? main = null;
        if (withConnection)
        {
            var launch = DevelopmentLaunchOptions.Parse(new[] { "--development-server" });
            var devClient = launch.CreateClient();
            connection = new ConnectionViewModel(launch, devClient, coordinator);
        }

        if (withMain)
        {
            var launch = DevelopmentLaunchOptions.Parse(new[] { "--development-server" });
            main = new MainViewModel(launch, coordinator);
            connection = main.Connection;
        }

        harness = new Harness
        {
            Server = server,
            Client = client,
            Key = key,
            Time = time,
            Coordinator = coordinator,
            Connection = connection,
            Main = main,
        };
        return harness;
    }

    private static async Task SignInOptionalAsync(Harness harness, long expiresAtUnix, string user = "alice")
    {
        var keyHex = harness.Key.PublicKeyHex;
        harness.ExpiresAtUnix = expiresAtUnix;
        // Responder is installed by the caller via closure; this helper only
        // drives begin+complete against whatever the harness serves.
        var pending = await harness.Client.BeginChallengeAsync(user, "pw", CancellationToken.None);
        await harness.Client.CompleteChallengeAsync(pending, null, CancellationToken.None);
    }

    [Fact]
    public async Task ActualClockExpiry_DropsSessionWithoutAnotherRequest()
    {
        // Causal red regression retained from coordinator review (pinned HTTPS).
        using var pki = TestDeploymentPki.Create("HS expiry review CA");
        using var key = Ed25519DeviceKey.Create();
        long expires = 0;
        int inventoryRequests = 0;
        var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            head =>
            {
                if (head.Contains("/complete", StringComparison.Ordinal))
                {
                    expires = NowPlus(2);
                    return TestHttpScripts.Json(
                        Encoding.UTF8.GetString(LoginJson(
                            "review-token-not-logged", expires, "alice", key.PublicKeyHex)));
                }

                if (head.Contains("/computers", StringComparison.Ordinal))
                {
                    Interlocked.Increment(ref inventoryRequests);
                    return TestHttpScripts.Json("{\"computers\":[]}");
                }

                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(BeginJson(
                        "review-challenge", "review-challenge-token", key.PublicKeyHex, NowPlus(90), false)),
                    status: 201);
            });
        var trust = TrustFor(pki, server.Origin);
        await using (server)
        using (var client = new V2DeviceKeyChallengeClient(trust, key))
        {
            var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
            await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
            Assert.True(client.HasSession);
            var remaining = DateTimeOffset.FromUnixTimeSeconds(expires) - DateTimeOffset.UtcNow
                + TimeSpan.FromMilliseconds(150);
            if (remaining > TimeSpan.Zero)
            {
                await Task.Delay(remaining);
            }

            Assert.False(client.HasSession);
            var error = await Assert.ThrowsAsync<ServerClientException>(
                () => client.GetInventoryAsync(CancellationToken.None));
            Assert.Equal(ServerClientFailure.NotConnected, error.Failure);
            Assert.Equal(0, Volatile.Read(ref inventoryRequests));
        }
    }

    [Fact]
    public async Task Deadline_DropsBearer_AndRefusesAuthorizedRequest()
    {
        using var pki = TestDeploymentPki.Create("HS expiry drop CA");
        // Fixed base so reception/expiry remaining is exactly 1.6s (expires_at_unix
        // is whole seconds; base .400s ⇒ floor+2 - .400 = 1.600s).
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, 400, TimeSpan.Zero));
        long expires = 0;
        int inventoryRequests = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref h.CompleteRequests);
                expires = h.Time.GetUtcNow().ToUnixTimeSeconds() + 2;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok-secret", expires, "alice", h.Key.PublicKeyHex)));
            }

            if (head.Contains("/computers", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref inventoryRequests);
                return TestHttpScripts.Json("{\"computers\":[]}");
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "c1", "t1", h.Key.PublicKeyHex,
                    h.Time.GetUtcNow().ToUnixTimeSeconds() + 90, false)),
                status: 201);
        });
        await using (harness)
        {
            await SignInOptionalAsync(harness, expires);
            Assert.True(harness.Client.HasSession);

            time.Advance(TimeSpan.FromMilliseconds(1500));
            Assert.True(harness.Client.HasSession);

            // Subsecond past the monotonic deadline (1.6s).
            time.Advance(TimeSpan.FromMilliseconds(200));
            Assert.False(harness.Client.HasSession);

            var error = await Assert.ThrowsAsync<ServerClientException>(
                () => harness.Client.GetInventoryAsync(CancellationToken.None));
            Assert.Equal(ServerClientFailure.NotConnected, error.Failure);
            Assert.Equal(0, Volatile.Read(ref inventoryRequests));
        }
    }

    [Fact]
    public async Task WallClockRollback_CannotExtendMonotonicBound()
    {
        using var pki = TestDeploymentPki.Create("HS expiry rollback CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        long expires = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                expires = h.Time.GetUtcNow().ToUnixTimeSeconds() + 3;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", expires, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            await SignInOptionalAsync(harness, expires);
            Assert.True(harness.Client.HasSession);

            // Wall rollback of two hours must not revive or extend the session.
            time.JumpWallClock(TimeSpan.FromHours(-2));
            Assert.True(harness.Client.HasSession, "Rollback alone must not expire early");

            time.Advance(TimeSpan.FromSeconds(3));
            Assert.False(harness.Client.HasSession);
        }
    }

    [Fact]
    public async Task WallClockForwardJump_FailsClosed()
    {
        using var pki = TestDeploymentPki.Create("HS expiry forward CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        long expires = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                expires = h.Time.GetUtcNow().ToUnixTimeSeconds() + 3600;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", expires, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            await SignInOptionalAsync(harness, expires);
            Assert.True(harness.Client.HasSession);

            time.JumpWallClock(TimeSpan.FromHours(2));
            Assert.False(harness.Client.HasSession, "Forward jump past contracted expiry must fail closed");
        }
    }

    [Fact]
    public async Task AutomaticDeadline_ResetsClientCoordinatorAndConnectionViewModel()
    {
        using var pki = TestDeploymentPki.Create("HS expiry auto CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        long expires = 0;
        int sessionsExpired = 0;
        int sessionLost = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                expires = h.Time.GetUtcNow().ToUnixTimeSeconds() + 2;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", expires, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        }, withCoordinator: true, withConnection: true);
        await using (harness)
        {
            var coordinator = harness.Coordinator!;
            var connection = harness.Connection!;
            harness.Client.SessionExpired += (_, _) => Interlocked.Increment(ref sessionsExpired);
            connection.SessionLost += (_, _) => Interlocked.Increment(ref sessionLost);

            coordinator.Username = "alice";
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.Equal(V2SignInPhase.SignedIn, coordinator.Phase);
            Assert.Equal(ConnectionUiState.SignedIn, connection.State);
            Assert.Equal("alice", connection.SignedInAccountName);
            Assert.True(harness.Client.HasSession);

            time.Advance(TimeSpan.FromMilliseconds(2100));

            Assert.False(harness.Client.HasSession);
            Assert.True(Volatile.Read(ref sessionsExpired) >= 1);
            Assert.Equal(V2SignInPhase.Ready, coordinator.Phase);
            Assert.False(coordinator.IsSignedIn);
            Assert.Equal(string.Empty, coordinator.SignedInAccountName);
            Assert.Equal(string.Empty, coordinator.ManagerLifecycleState);
            Assert.False(coordinator.RequiresTotp);
            Assert.Contains("expired", coordinator.StatusMessage, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(ConnectionUiState.ReadyForDevelopmentSignin, connection.State);
            Assert.Equal(string.Empty, connection.SignedInAccountName);
            Assert.Equal(string.Empty, connection.ManagerLifecycleState);
            Assert.False(connection.RequiresTotp);
            Assert.True(Volatile.Read(ref sessionLost) >= 1);
        }
    }

    [Fact]
    public async Task AutomaticDeadline_ClearsMainViewModelInventoryAndSelection()
    {
        using var pki = TestDeploymentPki.Create("HS expiry main CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        long expires = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                expires = h.Time.GetUtcNow().ToUnixTimeSeconds() + 2;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", expires, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        }, withCoordinator: true, withMain: true);
        await using (harness)
        {
            var coordinator = harness.Coordinator!;
            var main = harness.Main!;
            coordinator.Username = "alice";
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.Equal(V2SignInPhase.SignedIn, coordinator.Phase);

            var record = new Helicoid.Domain.Model.ComputerRecord(
                Helicoid.Domain.Model.ComputerId.Parse("comp-1"),
                "PC-1",
                Helicoid.Domain.Model.ComputerStatus.Online);
            main.ApplyServerInventory(new[] { record });
            main.SelectTile(record.Id, additive: false);
            Assert.True(main.Tiles.Count > 0);
            Assert.True(main.Overview.Selection.Count > 0);

            time.Advance(TimeSpan.FromMilliseconds(2100));

            Assert.False(harness.Client.HasSession);
            Assert.Empty(main.Tiles);
            Assert.Equal(0, main.Overview.Selection.Count);
        }
    }

    [Fact]
    public async Task SignOut_Dispose_Cancel_DoNotEraseReplacement()
    {
        using var pki = TestDeploymentPki.Create("HS expiry replace CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        long expiresA = 0;
        long expiresB = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var token = h.CompleteRequests == 0 ? "tok-a" : "tok-b";
                Interlocked.Increment(ref h.CompleteRequests);
                var exp = h.CompleteRequests == 1
                    ? h.Time.GetUtcNow().ToUnixTimeSeconds() + 2
                    : h.Time.GetUtcNow().ToUnixTimeSeconds() + 3600;
                if (h.CompleteRequests == 1)
                {
                    expiresA = exp;
                }
                else
                {
                    expiresB = exp;
                }

                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(token, exp, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        }, withCoordinator: true);
        await using (harness)
        {
            var client = harness.Client;
            var coordinator = harness.Coordinator!;

            coordinator.Username = "alice";
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.True(client.HasSession);

            // Replacement sign-in before the first deadline.
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.True(client.HasSession);
            Assert.Equal(V2SignInPhase.SignedIn, coordinator.Phase);

            // Stale timer from generation A must not clear replacement B.
            time.Advance(TimeSpan.FromSeconds(2));
            Assert.True(client.HasSession);
            Assert.Equal(V2SignInPhase.SignedIn, coordinator.Phase);

            coordinator.SignOut();
            Assert.False(client.HasSession);
            Assert.Equal(V2SignInPhase.Ready, coordinator.Phase);
        }
    }

    [Fact]
    public async Task StaleUnauthorizedResponse_DoesNotClearReplacementSession()
    {
        using var pki = TestDeploymentPki.Create("HS expiry stale401 CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var firstInventoryGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int inventoryCalls = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref h.CompleteRequests);
                var exp = h.Time.GetUtcNow().ToUnixTimeSeconds() + 3600;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok-" + n, exp, "alice", h.Key.PublicKeyHex)));
            }

            if (head.Contains("/computers", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref inventoryCalls);
                if (n == 1)
                {
                    firstInventoryGate.Task.Wait(TimeSpan.FromSeconds(5));
                    return TestHttpScripts.Json(
                        "{\"error\":{\"code\":\"unauthorized\",\"message\":\"stale\"}}",
                        status: 401);
                }

                return TestHttpScripts.Json("{\"computers\":[]}");
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            var client = harness.Client;
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
            Assert.True(client.HasSession);

            var staleInventory = client.GetInventoryAsync(CancellationToken.None);
            await Task.Delay(50);

            // Replacement while the stale 401 is still in flight.
            var pending2 = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            await client.CompleteChallengeAsync(pending2, null, CancellationToken.None);
            Assert.True(client.HasSession);

            firstInventoryGate.TrySetResult();
            await Assert.ThrowsAsync<ServerClientException>(() => staleInventory);
            Assert.True(client.HasSession, "Stale 401 must not clear the replacement bearer");
        }
    }

    [Fact]
    public async Task ExpiredSession_LeavesNoStrongRetention()
    {
        using var pki = TestDeploymentPki.Create("HS expiry weak CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session", NowPlus(3600), "alice", keyHex)))
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", keyHex, NowPlus(90), false))));
        var weak = await SignInAndAbandonAsync(pki, server, key);
        for (var n = 0; n < 3; n++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            await Task.Delay(30);
        }

        Assert.False(weak.TryGetTarget(out _));
    }

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static async Task<WeakReference<V2DeviceKeyChallengeClient>> SignInAndAbandonAsync(
        TestDeploymentPki pki, TestHttpsServer server, Ed25519DeviceKey key)
    {
        var client = new V2DeviceKeyChallengeClient(TrustFor(pki, server.Origin), key);
        var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
        return new WeakReference<V2DeviceKeyChallengeClient>(client);
    }

    [Fact]
    public async Task SessionReplies_DoNotExtendDeadline()
    {
        using var pki = TestDeploymentPki.Create("HS expiry no-renew CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        long expires = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                expires = h.Time.GetUtcNow().ToUnixTimeSeconds() + 2;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", expires, "alice", h.Key.PublicKeyHex)));
            }

            if (head.Contains("/auth/session", StringComparison.Ordinal))
            {
                // Server reports a far-future expiry; client must not renew.
                return TestHttpScripts.Json(
                    "{\"account\":{\"id\":\"a1\",\"username\":\"alice\",\"state\":\"active\"," +
                    "\"capabilities\":{},\"revision\":1}" +
                    ",\"expires_at_unix\":" + (h.Time.GetUtcNow().ToUnixTimeSeconds() + 7200) + "}");
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            await SignInOptionalAsync(harness, expires);
            Assert.True(harness.Client.HasSession);

            var session = await harness.Client.GetSessionAsync(CancellationToken.None);
            Assert.NotNull(session.Account);

            time.Advance(TimeSpan.FromMilliseconds(2100));
            Assert.False(harness.Client.HasSession);
        }
    }

    [Fact]
    public async Task Dispose_CancelsDeadlineAndLeavesNoSession()
    {
        using var pki = TestDeploymentPki.Create("HS expiry dispose CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var exp = h.Time.GetUtcNow().ToUnixTimeSeconds() + 3600;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", exp, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        }, withCoordinator: true);
        await using (harness)
        {
            harness.Coordinator!.Username = "alice";
            await harness.Coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.True(harness.Client.HasSession);
            harness.Coordinator.Dispose();
            Assert.False(harness.Client.HasSession);
            // Time advance after dispose must not throw or resurrect state.
            time.Advance(TimeSpan.FromHours(1));
        }
    }

    [Fact]
    public async Task EarlyTimerFire_RearmsAndStillExpiresAtMonotonicDeadline()
    {
        using var pki = TestDeploymentPki.Create("HS expiry early CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        long expires = 0;
        int expiredEvents = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                // 2s remaining at reception; timer scheduled for that interval.
                expires = h.Time.GetUtcNow().AddSeconds(2).ToUnixTimeSeconds();
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", expires, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            harness.Client.SessionExpired += (_, _) => Interlocked.Increment(ref expiredEvents);
            await SignInOptionalAsync(harness, expires);
            Assert.True(harness.Client.HasSession);

            // Genuine early one-shot callback: timer is disabled first and
            // fired before its due time. Must rearm, not expire and not drop
            // the deadline signal.
            time.FireTimerEarly();
            Assert.Equal(0, Volatile.Read(ref expiredEvents));
            Assert.True(harness.Client.HasSession);

            // Advance past the monotonic deadline. SessionExpired must fire
            // from the rearmed timer before any lazy HasSession getter.
            time.Advance(TimeSpan.FromMilliseconds(2100));
            Assert.Equal(1, Volatile.Read(ref expiredEvents));
            Assert.False(harness.Client.HasSession);
        }
    }

    [Fact]
    public async Task StaleGetSessionReply_DoesNotClearReplacement()
    {
        using var pki = TestDeploymentPki.Create("HS expiry stale session CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var firstSessionGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int sessionCalls = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref h.CompleteRequests);
                var exp = h.Time.GetUtcNow().ToUnixTimeSeconds() + (n == 1 ? 2 : 3600);
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok-" + n, exp, "alice", h.Key.PublicKeyHex)));
            }

            if (head.Contains("/auth/session", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref sessionCalls);
                if (n == 1)
                {
                    firstSessionGate.Task.Wait(TimeSpan.FromSeconds(5));
                    // Stale body: expired wall-clock session.
                    return TestHttpScripts.Json(
                        "{\"account\":{\"id\":\"a1\",\"username\":\"alice\",\"state\":\"active\"," +
                        "\"capabilities\":{},\"revision\":1}" +
                        ",\"expires_at_unix\":" + (h.Time.GetUtcNow().ToUnixTimeSeconds() - 10) + "}");
                }

                return TestHttpScripts.Json(
                    "{\"account\":{\"id\":\"a1\",\"username\":\"alice\",\"state\":\"active\"," +
                    "\"capabilities\":{},\"revision\":1}" +
                    ",\"expires_at_unix\":" + (h.Time.GetUtcNow().ToUnixTimeSeconds() + 3600) + "}");
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            var client = harness.Client;
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
            Assert.True(client.HasSession);

            var staleSession = client.GetSessionAsync(CancellationToken.None);
            await Task.Delay(50);

            var pending2 = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            await client.CompleteChallengeAsync(pending2, null, CancellationToken.None);
            Assert.True(client.HasSession);

            firstSessionGate.TrySetResult();
            await Assert.ThrowsAsync<ServerClientException>(() => staleSession);
            Assert.True(client.HasSession, "Stale expired session body must not clear the replacement bearer");
        }
    }

    [Fact]
    public async Task DelayedExpiryNotification_CannotResetReplacementSignIn()
    {
        using var pki = TestDeploymentPki.Create("HS expiry delayed notify CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var completions = 0;
        // Start without a coordinator so the blocker can subscribe first.
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref completions);
                var exp = h.Time.GetUtcNow().ToUnixTimeSeconds() + (n == 1 ? 2 : 3600);
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok-" + n, exp, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c" + completions, "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            var client = harness.Client;
            using var release = new ManualResetEventSlim();
            var blocked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            // Blocker is subscribed BEFORE the coordinator so it runs first
            // and holds the notification while a replacement can land.
            client.SessionExpired += (_, _) =>
            {
                blocked.TrySetResult();
                if (!release.Wait(TimeSpan.FromSeconds(8)))
                {
                    throw new TimeoutException("expiry blocker was not released");
                }
            };
            using var coordinator = new V2SignInCoordinator(client) { Username = "alice" };
            client.SessionExpired += (_, _) => drained.TrySetResult();

            Task? firing = null;
            try
            {
                await coordinator.SignInAsync("pw", CancellationToken.None);
                Assert.True(coordinator.IsSignedIn);

                // Expiry advance on an owned task so the blocked handler can
                // run concurrently with the replacement sign-in.
                firing = Task.Run(() => time.Advance(TimeSpan.FromMilliseconds(2100)));
                await blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));

                // Replacement sign-in while the old notification is paused.
                await coordinator.SignInAsync("pw", CancellationToken.None);
                Assert.True(coordinator.IsSignedIn);
                Assert.True(client.HasSession);

                release.Set();
                await drained.Task.WaitAsync(TimeSpan.FromSeconds(3));

                Assert.True(client.HasSession);
                Assert.True(coordinator.IsSignedIn, "Stale expiry notification must not reset the replacement sign-in");
            }
            finally
            {
                release.Set();
                if (firing is not null)
                {
                    await firing.WaitAsync(TimeSpan.FromSeconds(3));
                }
            }
        }
    }

    [Fact]
    public async Task StaleLogout_DoesNotClearReplacement()
    {
        using var pki = TestDeploymentPki.Create("HS expiry stale logout CA");
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var firstLogoutGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int logoutCalls = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref h.CompleteRequests);
                var exp = h.Time.GetUtcNow().ToUnixTimeSeconds() + 3600;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok-" + n, exp, "alice", h.Key.PublicKeyHex)));
            }

            if (head.Contains("/logout", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref logoutCalls);
                if (n == 1)
                {
                    firstLogoutGate.Task.Wait(TimeSpan.FromSeconds(5));
                }

                return TestHttpScripts.Json("{}", status: 200);
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("c1", "t1", h.Key.PublicKeyHex, NowPlus(90), false)),
                status: 201);
        });
        await using (harness)
        {
            var client = harness.Client;
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
            Assert.True(client.HasSession);

            var staleLogout = client.LogoutAsync(CancellationToken.None);
            await Task.Delay(50);

            var pending2 = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            await client.CompleteChallengeAsync(pending2, null, CancellationToken.None);
            Assert.True(client.HasSession);

            firstLogoutGate.TrySetResult();
            // Stale logout response is denied at the shared fence; the
            // replacement bearer must remain installed.
            await Assert.ThrowsAsync<ServerClientException>(() => staleLogout);
            Assert.True(client.HasSession, "Stale logout must not clear the replacement bearer");
        }
    }

    [Fact]
    public async Task SubSecondDeadline_FractionalReceptionIsHonored()
    {
        using var pki = TestDeploymentPki.Create("HS expiry frac CA");
        // Fixed fractional base: reception at .400s, expires_at_unix = floor+2
        // ⇒ remaining exactly 1.600s. Proves sub-second deadline, not whole seconds.
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, 400, TimeSpan.Zero));
        long expires = 0;
        var harness = Start(pki, time, (h, head) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                // Contract expires_at_unix is whole seconds; remaining at
                // reception is fractional (1.600s).
                expires = h.Time.GetUtcNow().ToUnixTimeSeconds() + 2;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson("tok", expires, "alice", h.Key.PublicKeyHex)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "c1", "t1", h.Key.PublicKeyHex,
                    h.Time.GetUtcNow().ToUnixTimeSeconds() + 90, false)),
                status: 201);
        });
        await using (harness)
        {
            await SignInOptionalAsync(harness, expires);
            Assert.True(harness.Client.HasSession);

            time.Advance(TimeSpan.FromMilliseconds(1500));
            Assert.True(harness.Client.HasSession);

            time.Advance(TimeSpan.FromMilliseconds(200));
            Assert.False(harness.Client.HasSession);
        }
    }
}
