using System.Net;
using System.Text;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Conditional TOTP UI-state and secret-clearing proofs for the native
/// sign-in coordinator at its public seam.
/// </summary>
public class V2SignInCoordinatorTests
{
    private const string TrustedDeployment = "dep-auth-v2-1";

    private static DeploymentTlsTrust TrustFor(TestDeploymentPki pki, Uri origin) =>
        DeploymentTlsTrust.Create(
            TrustedDeployment,
            origin,
            pki.CaDer,
            pki.CaFingerprintSha256Hex);

    private static long NowPlus(int seconds) => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + seconds;

    private static (TestHttpsServer Server, V2DeviceKeyChallengeClient Client, V2SignInCoordinator Coordinator, Ed25519DeviceKey Key)
        Start(
            TestDeploymentPki pki,
            Func<string, byte[]> responder,
            Ed25519DeviceKey? key = null)
    {
        var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            responder);
        var trust = TrustFor(pki, server.Origin);
        var deviceKey = key ?? Ed25519DeviceKey.Create();
        var client = new V2DeviceKeyChallengeClient(trust, deviceKey);
        var coordinator = new V2SignInCoordinator(client);
        return (server, client, coordinator, deviceKey);
    }

    private static byte[] BeginRequired(string keyHex) =>
        Encoding.UTF8.GetBytes($$"""
            {"challenge_id":"c1","challenge_token":"t1","operation":"session",
             "manager_public_key":"{{keyHex}}","deployment_id":"{{TrustedDeployment}}",
             "expires_at_unix":{{NowPlus(90)}},"mfa_required":true}
            """);

    private static byte[] BeginOptional(string keyHex) =>
        Encoding.UTF8.GetBytes($$"""
            {"challenge_id":"c2","challenge_token":"t2","operation":"session",
             "manager_public_key":"{{keyHex}}","deployment_id":"{{TrustedDeployment}}",
             "expires_at_unix":{{NowPlus(90)}},"mfa_required":false}
            """);

    private static byte[] BeginJson(
        string challengeId,
        string challengeToken,
        string operation,
        string managerKeyHex,
        string deploymentId,
        long expiresAtUnix,
        bool mfaRequired)
    {
        return Encoding.UTF8.GetBytes(
            "{\"challenge_id\":\"" + challengeId +
            "\",\"challenge_token\":\"" + challengeToken +
            "\",\"operation\":\"" + operation +
            "\",\"manager_public_key\":\"" + managerKeyHex +
            "\",\"deployment_id\":\"" + deploymentId +
            "\",\"expires_at_unix\":" + expiresAtUnix +
            ",\"mfa_required\":" + (mfaRequired ? "true" : "false") + "}");
    }

    private static byte[] Login(string keyHex, string user, bool mfaRequired, bool mfaAvailable) =>
        Encoding.UTF8.GetBytes($$"""
            {"token":"tok","expires_at_unix":{{NowPlus(3600)}},
             "account":{"id":"a1","username":"{{user}}","state":"active",
                        "capabilities":{},"revision":1},
             "manager":{"id":"m1","public_identity":"key:{{keyHex}}","lifecycle_state":"approved"},
             "mfa":{"required":{{(mfaRequired ? "true" : "false")}},
                    "available":{{(mfaAvailable ? "true" : "false")}}},
             "manager_public_key":"{{keyHex}}"}
            """);

    [Fact]
    public async Task NullClient_KeepsExplicitUnavailability()
    {
        using var coordinator = new V2SignInCoordinator(null);
        Assert.Equal(V2SignInPhase.Unavailable, coordinator.Phase);
        Assert.False(coordinator.RequiresTotp);
        Assert.False(coordinator.CanStart);

        await coordinator.SignInAsync("pw", CancellationToken.None);
        Assert.Equal(V2SignInPhase.Unavailable, coordinator.Phase);
        Assert.DoesNotContain("password", coordinator.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RequiredChallenge_ShowsAwaitingTotp_ThenSignsIn()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Coord CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var phases = new List<V2SignInPhase>();
        var (server, client, coordinator, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "alice", true, true)));
            }

            return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginRequired(keyHex)), status: 201);
        }, key);

        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(V2SignInCoordinator.Phase))
                {
                    phases.Add(coordinator.Phase);
                }
            };

            coordinator.Username = "alice";
            await coordinator.SignInAsync("pw", CancellationToken.None);

            Assert.Equal(V2SignInPhase.AwaitingTotp, coordinator.Phase);
            Assert.True(coordinator.RequiresTotp);
            Assert.True(coordinator.CanCompleteTotp);

            await coordinator.CompleteWithTotpAsync("123456", CancellationToken.None);
            Assert.Equal(V2SignInPhase.SignedIn, coordinator.Phase);
            Assert.False(coordinator.RequiresTotp);
            Assert.Equal("alice", coordinator.SignedInAccountName);
            Assert.Contains(V2SignInPhase.AwaitingTotp, phases);
            Assert.Contains(V2SignInPhase.SignedIn, phases);
        }
    }

    [Fact]
    public async Task OptionalChallenge_SignsInWithoutTotp()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Coord CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, coordinator, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                Assert.DoesNotContain("totp_code", head, StringComparison.Ordinal);
                return TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "bob", false, false)));
            }

            return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginOptional(keyHex)), status: 201);
        }, key);

        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.Username = "bob";
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.Equal(V2SignInPhase.SignedIn, coordinator.Phase);
            Assert.False(coordinator.RequiresTotp);
        }
    }

    [Fact]
    public async Task InvalidTotp_RemainsAwaitingTotp()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Coord CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, coordinator, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "alice", true, true)));
            }

            return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginRequired(keyHex)), status: 201);
        }, key);

        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.Username = "alice";
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.Equal(V2SignInPhase.AwaitingTotp, coordinator.Phase);

            await coordinator.CompleteWithTotpAsync("12", CancellationToken.None);
            Assert.Equal(V2SignInPhase.AwaitingTotp, coordinator.Phase);

            await coordinator.CompleteWithTotpAsync("abcdef", CancellationToken.None);
            Assert.Equal(V2SignInPhase.AwaitingTotp, coordinator.Phase);
        }
    }

    [Fact]
    public async Task Cancel_ClearsPendingAndReturnsToReady()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Coord CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, coordinator, _) = Start(pki, _ =>
            TestHttpScripts.Json(Encoding.UTF8.GetString(BeginRequired(keyHex)), status: 201), key);

        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.Username = "alice";
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.Equal(V2SignInPhase.AwaitingTotp, coordinator.Phase);

            coordinator.Cancel();
            Assert.Equal(V2SignInPhase.Ready, coordinator.Phase);
            Assert.False(coordinator.RequiresTotp);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task SignOut_AfterSignIn_ClearsSession()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Coord CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, coordinator, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "alice", false, false)));
            }

            return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginOptional(keyHex)), status: 201);
        }, key);

        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.Username = "alice";
            await coordinator.SignInAsync("pw", CancellationToken.None);
            Assert.Equal(V2SignInPhase.SignedIn, coordinator.Phase);
            Assert.True(client.HasSession);

            coordinator.SignOut();
            Assert.Equal(V2SignInPhase.Ready, coordinator.Phase);
            Assert.False(client.HasSession);
            Assert.Equal(string.Empty, coordinator.SignedInAccountName);
        }
    }

    [Fact]
    public void ToStringAndStatus_DoNotEchoSecrets()
    {
        var pending = new PendingAuthChallenge(
            "chal",
            Encoding.UTF8.GetBytes("secret-token"),
            "dep",
            "session",
            "aa",
            NowPlus(60),
            mfaRequired: true);

        Assert.Equal("PendingAuthChallenge", pending.ToString());
        Assert.DoesNotContain("secret-token", pending.ToString(), StringComparison.Ordinal);

        pending.Clear();
        Assert.True(pending.IsCleared);
        Assert.Equal("PendingAuthChallenge(cleared)", pending.ToString());
        Assert.DoesNotContain("secret-token", pending.ToString(), StringComparison.Ordinal);
    }

    // =================================================================
    // Causal race regressions (15 Oct coordinator race review).
    // Actual client + coordinator over real TLS; controlled UI context.
    // =================================================================

    [Fact]
    public async Task Coordinator_CancelAfterClientSuccessBeforeUiInstall_DoesNotSignIn()
    {
        using var pki = TestDeploymentPki.Create("Coordinator independent CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;
        var (server, client, coordinator, _) = Start(pki, head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "alice", false, false)))
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginOptional(keyHex)), status: 201), key);
        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.Username = "alice";
            var context = new CoordinatorDeferredContext();
            var previous = SynchronizationContext.Current;
            Task operation;
            try
            {
                SynchronizationContext.SetSynchronizationContext(context);
                operation = coordinator.SignInAsync("fixture-pass", CancellationToken.None);
            }
            finally { SynchronizationContext.SetSynchronizationContext(previous); }
            context.Run(await context.TakeAsync());
            var completion = await context.TakeAsync();
            Assert.True(client.HasSession); // client succeeded; UI continuation is held
            coordinator.Cancel();
            context.Run(completion);
            for (var i = 0; !operation.IsCompleted && i < 5; i++)
                context.Run(await context.TakeAsync());
            await operation.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(coordinator.IsSignedIn);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task Coordinator_ObsoleteCompletionCannotEraseReplacementBearer()
    {
        using var pki = TestDeploymentPki.Create("Coordinator replacement CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;
        var completed = 0;
        var (server, client, coordinator, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref completed);
                var json = Encoding.UTF8.GetString(Login(keyHex, "alice", false, false))
                    .Replace("\"token\":\"tok\"", "\"token\":\"tok-" + n + "\"", StringComparison.Ordinal);
                return TestHttpScripts.Json(json);
            }

            return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginOptional(keyHex)), status: 201);
        }, key);
        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.Username = "alice";
            var context = new CoordinatorDeferredContext();
            var previous = SynchronizationContext.Current;
            Task oldOperation;
            try
            {
                SynchronizationContext.SetSynchronizationContext(context);
                oldOperation = coordinator.SignInAsync("fixture-pass", CancellationToken.None);
            }
            finally { SynchronizationContext.SetSynchronizationContext(previous); }
            context.Run(await context.TakeAsync());
            var oldCompletion = await context.TakeAsync();
            Assert.True(client.HasSession);
            await coordinator.SignInAsync("replacement-fixture-pass", CancellationToken.None);
            Assert.True(coordinator.IsSignedIn);
            Assert.True(client.HasSession);
            context.Run(oldCompletion);
            for (var i = 0; !oldOperation.IsCompleted && i < 5; i++)
                context.Run(await context.TakeAsync());
            await oldOperation.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(coordinator.IsSignedIn);
            Assert.True(client.HasSession, "Obsolete completion cleanup must preserve replacement bearer");
        }
    }

    [Fact]
    public async Task Coordinator_OldRequestErrorAfterReplacementBegin_DoesNotResetNewAttempt()
    {
        using var pki = TestDeploymentPki.Create("Coordinator race CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;
        var firstBeginGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (server, client, coordinator, _) = Start(pki, head =>
        {
            if (head.Contains("/v2/auth/challenge", StringComparison.Ordinal)
                && !head.Contains("/complete", StringComparison.Ordinal))
            {
                if (head.Contains("user-old", StringComparison.Ordinal))
                {
                    // Obsolete begin stalls, then fails.
                    firstBeginGate.Task.Wait(TimeSpan.FromSeconds(5));
                    return TestHttpScripts.Json(
                        "{\"error\":{\"code\":\"internal\",\"message\":\"first failed\"}}",
                        status: 500);
                }

                return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginRequired(keyHex)), status: 201);
            }

            return TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "alice", true, true)));
        }, key);

        await using (server)
        using (client)
        using (coordinator)
        {
            coordinator.Username = "user-old";
            var first = coordinator.SignInAsync("pw-1", CancellationToken.None);
            // Replacement attempt while the first is still in flight.
            coordinator.Username = "user-new";
            var second = coordinator.SignInAsync("pw-2", CancellationToken.None);
            firstBeginGate.TrySetResult();
            await first.WaitAsync(TimeSpan.FromSeconds(10));
            await second.WaitAsync(TimeSpan.FromSeconds(10));

            // The replacement attempt owns the UI state; the obsolete failure
            // must not clear its pending challenge or reset it away from AwaitingTotp.
            Assert.Equal(V2SignInPhase.AwaitingTotp, coordinator.Phase);
            Assert.True(coordinator.RequiresTotp);
        }
    }

    [Fact]
    public async Task Client_OverlappingBegins_OutOfOrderLateReply_DoesNotReplaceNewerPending()
    {
        using var pki = TestDeploymentPki.Create("Client race CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;
        var firstBeginGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (server, client, _, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "alice", false, false)));
            }

            if (head.Contains("user-old", StringComparison.Ordinal))
            {
                firstBeginGate.Task.Wait(TimeSpan.FromSeconds(5));
                // Late first reply: a different challenge id.
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(BeginJson("chal-old", "tok-old", "session", keyHex, TrustedDeployment, NowPlus(60), false)),
                    status: 201);
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("chal-new", "tok-new", "session", keyHex, TrustedDeployment, NowPlus(60), false)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var first = client.BeginChallengeAsync("user-old", "pw-1", CancellationToken.None);
            // Give first a chance to reach the server before the replacement.
            await Task.Delay(50);
            var second = client.BeginChallengeAsync("user-new", "pw-2", CancellationToken.None);
            firstBeginGate.TrySetResult();

            // Out-of-order completion: the late first must not replace the newer pending.
            PendingAuthChallenge? secondPending = null;
            try
            {
                secondPending = await second.WaitAsync(TimeSpan.FromSeconds(10));
            }
            finally
            {
                try { _ = await first.WaitAsync(TimeSpan.FromSeconds(10)); }
                catch (ServerClientException)
                {
                    // Late obsolete begin may fail after being superseded.
                }
            }

            Assert.NotNull(secondPending);
            Assert.Equal("chal-new", secondPending!.ChallengeId);
            Assert.False(secondPending.IsCleared);

            var login = await client.CompleteChallengeAsync(secondPending, null, CancellationToken.None);
            Assert.Equal("tok", login.Token);
        }
    }

    [Fact]
    public async Task Client_StaleCleanup_DoesNotEraseNewerBearerOrChallenge()
    {
        using var pki = TestDeploymentPki.Create("Client stale CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;
        var firstBeginGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var firstCts = new CancellationTokenSource();
        var (server, client, _, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(Encoding.UTF8.GetString(Login(keyHex, "alice", false, false)));
            }

            if (head.Contains("user-old", StringComparison.Ordinal))
            {
                firstBeginGate.Task.Wait(TimeSpan.FromSeconds(5));
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(BeginJson("chal-old", "tok-old", "session", keyHex, TrustedDeployment, NowPlus(60), false)),
                    status: 201);
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson("chal-new", "tok-new", "session", keyHex, TrustedDeployment, NowPlus(60), false)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var first = client.BeginChallengeAsync("user-old", "pw-1", firstCts.Token);
            await Task.Delay(50);
            var second = await client.BeginChallengeAsync("user-new", "pw-2", CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal("chal-new", second.ChallengeId);

            var login = await client.CompleteChallengeAsync(second, null, CancellationToken.None);
            Assert.True(client.HasSession);

            // Cancel/complete the obsolete begin; it must not erase the installed bearer
            // or the fact that the new challenge was already consumed.
            firstCts.Cancel();
            firstBeginGate.TrySetResult();
            try { _ = await first.WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (ServerClientException) { }
            catch (OperationCanceledException) { }

            Assert.True(client.HasSession);
        }
    }

    /// <summary>
    /// Controlled UI thread: continuations are posted and only run when the
    /// test invokes them, exposing install-point races.
    /// </summary>
    private sealed class CoordinatorDeferredContext : SynchronizationContext
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<(SendOrPostCallback Callback, object? State)> _queue = new();
        private readonly SemaphoreSlim _ready = new(0);

        public override void Post(SendOrPostCallback callback, object? state)
        {
            _queue.Enqueue((callback, state));
            _ready.Release();
        }

        public async Task<(SendOrPostCallback Callback, object? State)> TakeAsync()
        {
            Assert.True(await _ready.WaitAsync(TimeSpan.FromSeconds(5)), "Expected bounded UI continuation");
            Assert.True(_queue.TryDequeue(out var item));
            return item;
        }

        public void Run((SendOrPostCallback Callback, object? State) item)
        {
            var previous = Current;
            try { SetSynchronizationContext(this); item.Callback(item.State); }
            finally { SetSynchronizationContext(previous); }
        }
    }
}
