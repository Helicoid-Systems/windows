using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Real Ed25519 + pinned HTTPS proofs for the native v2 device-key challenge
/// client at public seams. Fixtures are test-only. Deployment identity is
/// always the independently supplied trust value, never health-discovered.
/// </summary>
public class V2AuthChallengeTests
{
    private const string TrustedDeployment = "dep-auth-v2-1";

    private static DeploymentTlsTrust TrustFor(TestDeploymentPki pki, Uri origin) =>
        DeploymentTlsTrust.Create(
            TrustedDeployment,
            origin,
            pki.CaDer,
            pki.CaFingerprintSha256Hex);

    private static string Hex32(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static long NowPlus(int seconds) => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + seconds;

    private static byte[] BeginJson(
        string challengeId,
        string challengeToken,
        string operation,
        string managerKeyHex,
        string deploymentId,
        long expiresAtUnix,
        bool? mfaRequired)
    {
        var mfa = mfaRequired is null ? "null" : mfaRequired.Value ? "true" : "false";
        return Encoding.UTF8.GetBytes($$"""
            {"challenge_id":"{{challengeId}}","challenge_token":"{{challengeToken}}",
             "operation":"{{operation}}","manager_public_key":"{{managerKeyHex}}",
             "deployment_id":"{{deploymentId}}","expires_at_unix":{{expiresAtUnix}},
             "mfa_required":{{mfa}}}
            """);
    }

    private static byte[] LoginJson(
        string token,
        long expiresAtUnix,
        string accountUser,
        string managerPublicKeyHex,
        string managerPublicIdentity,
        bool mfaRequired,
        bool mfaAvailable,
        string accountId = "acct-1")
    {
        return Encoding.UTF8.GetBytes($$"""
            {"token":"{{token}}","expires_at_unix":{{expiresAtUnix}},
             "account":{"id":"{{accountId}}","username":"{{accountUser}}","state":"active",
                        "capabilities":{"inventory":true},"revision":1},
             "manager":{"id":"mgr-1","public_identity":"{{managerPublicIdentity}}",
                        "friendly_name":"Device","lifecycle_state":"approved",
                        "approved_at_unix":1},
             "mfa":{"required":{{(mfaRequired ? "true" : "false")}},
                    "available":{{(mfaAvailable ? "true" : "false")}},
                    "reason":"totp_active"},
             "manager_public_key":"{{managerPublicKeyHex}}"}
            """);
    }

    private static (TestHttpsServer Server, V2DeviceKeyChallengeClient Client, Ed25519DeviceKey Key)
        Start(
            TestDeploymentPki pki,
            Func<string, byte[]> responder,
            Ed25519DeviceKey? key = null,
            TimeSpan? timeout = null)
    {
        var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            responder);
        var trust = TrustFor(pki, server.Origin);
        var deviceKey = key ?? Ed25519DeviceKey.Create();
        var client = new V2DeviceKeyChallengeClient(trust, deviceKey, timeout);
        return (server, client, deviceKey);
    }

    private static (TestHttpsServer Server, V2DeviceKeyChallengeClient Client, Ed25519DeviceKey Key)
        Start(
            TestDeploymentPki pki,
            Func<string, CancellationToken, Task<byte[]>> responder,
            Ed25519DeviceKey? key = null,
            TimeSpan? timeout = null)
    {
        var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback),
            responder);
        var trust = TrustFor(pki, server.Origin);
        var deviceKey = key ?? Ed25519DeviceKey.Create();
        var client = new V2DeviceKeyChallengeClient(trust, deviceKey, timeout);
        return (server, client, deviceKey);
    }

    [Fact]
    public void CanonicalMessage_MatchesFrozenLayout()
    {
        var keyHex = new string('a', 64);
        var message = AuthChallengeMessage.BuildCanonical(
            "dep-1",
            "chal-1",
            AuthChallengeBounds.SessionOperation,
            keyHex);

        Assert.Equal(
            "hs-auth-v2|deployment:dep-1|challenge:chal-1|operation:session|manager:" + keyHex,
            Encoding.UTF8.GetString(message));
    }

    [Fact]
    public async Task BeginAndComplete_RequiredMfa_InstallsSession()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/v2/auth/challenge/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-1", NowPlus(3600), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: true)),
                    status: 200);
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-1", "ctok-1", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw-not-logged", CancellationToken.None);
            Assert.True(pending.MfaRequired);

            var login = await client.CompleteChallengeAsync(pending, "123456", CancellationToken.None);
            Assert.Equal("tok-1", login.Token);
            Assert.True(client.HasSession);
            Assert.True(pending.IsCleared);
            Assert.True(client.HasSession);
            Assert.Equal("tok-1", login.Token);
        }
    }

    [Fact]
    public async Task MissingMfaRequiredFlag_IsTreatedAsRequired()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-2", NowPlus(3600), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: true)));
            }

            // mfa_required omitted entirely (JSON null / absent).
            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-2", "ctok-2", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: null)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            Assert.True(pending.MfaRequired);

            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, totpCode: null, CancellationToken.None));
            Assert.Equal(ServerClientFailure.BadRequest, ex.Failure);
        }
    }

    [Fact]
    public async Task OptionalMfa_OmitsTotp_AndAcceptsDisplayIdentityLabel()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                Assert.DoesNotContain("totp_code", head, StringComparison.Ordinal);
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-3", NowPlus(3600), "bob", keyHex,
                        managerPublicIdentity: "key:" + keyHex,
                        mfaRequired: false, mfaAvailable: false)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-3", "ctok-3", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: false)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("bob", "pw", CancellationToken.None);
            Assert.False(pending.MfaRequired);
            var login = await client.CompleteChallengeAsync(pending, totpCode: null, CancellationToken.None);
            Assert.Equal("bob", login.Account!.Username);
        }
    }

    [Fact]
    public async Task Begin_WrongDeployment_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, _ => TestHttpScripts.Json(
            Encoding.UTF8.GetString(BeginJson(
                "chal-4", "ctok-4", "session", keyHex, "other-deployment",
                NowPlus(90), mfaRequired: true)),
            status: 201), key);

        await using (server)
        using (client)
        {
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.BeginChallengeAsync("alice", "pw", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task Begin_WrongManagerKey_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        using var other = Ed25519DeviceKey.Create();

        var (server, client, _) = Start(pki, _ => TestHttpScripts.Json(
            Encoding.UTF8.GetString(BeginJson(
                "chal-5", "ctok-5", "session", other.PublicKeyHex, TrustedDeployment,
                NowPlus(90), mfaRequired: true)),
            status: 201), key);

        await using (server)
        using (client)
        {
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.BeginChallengeAsync("alice", "pw", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        }
    }

    [Fact]
    public async Task Begin_WrongOperation_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();

        var (server, client, _) = Start(pki, _ => TestHttpScripts.Json(
            Encoding.UTF8.GetString(BeginJson(
                "chal-6", "ctok-6", "enroll_manager", key.PublicKeyHex, TrustedDeployment,
                NowPlus(90), mfaRequired: true)),
            status: 201), key);

        await using (server)
        using (client)
        {
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.BeginChallengeAsync("alice", "pw", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        }
    }

    [Theory]
    [InlineData(-5)]
    [InlineData(125)]
    [InlineData(100000)]
    public async Task Begin_ExpiredOrOversizedExpiry_IsRefused(int offsetSeconds)
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var expires = NowPlus(offsetSeconds);

        var (server, client, _) = Start(pki, _ => TestHttpScripts.Json(
            Encoding.UTF8.GetString(BeginJson(
                "chal-7", "ctok-7", "session", key.PublicKeyHex, TrustedDeployment,
                expires, mfaRequired: true)),
            status: 201), key);

        await using (server)
        using (client)
        {
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.BeginChallengeAsync("alice", "pw", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        }
    }

    [Fact]
    public async Task Begin_OversizedChallengeId_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var huge = new string('x', AuthChallengeBounds.MaxIdentifierLength + 1);

        var (server, client, _) = Start(pki, _ => TestHttpScripts.Json(
            Encoding.UTF8.GetString(BeginJson(
                huge, "ctok-8", "session", key.PublicKeyHex, TrustedDeployment,
                NowPlus(60), mfaRequired: true)),
            status: 201), key);

        await using (server)
        using (client)
        {
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.BeginChallengeAsync("alice", "pw", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        }
    }

    [Fact]
    public async Task Complete_WrongReturnedManagerPublicKey_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        using var other = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                // Contract rev2: top-level manager_public_key must match signer.
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-9", NowPlus(3600), "alice", other.PublicKeyHex,
                        managerPublicIdentity: "key:" + other.PublicKeyHex,
                        mfaRequired: true, mfaAvailable: true)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-9", "ctok-9", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, "123456", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task Complete_MissingManagerPublicKey_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var json =
                    "{\"token\":\"tok-10\",\"expires_at_unix\":" + NowPlus(3600) +
                    ",\"account\":{\"id\":\"a\",\"username\":\"alice\",\"state\":\"active\"," +
                    "\"capabilities\":{},\"revision\":1}," +
                    "\"manager\":{\"id\":\"m\",\"public_identity\":\"key:display\",\"lifecycle_state\":\"approved\"}," +
                    "\"mfa\":{\"required\":true,\"available\":true}}";
                return TestHttpScripts.Json(json);
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-10", "ctok-10", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, "123456", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        }
    }

    [Fact]
    public async Task Complete_DisplayIdentityLabel_IsNotComparedToNakedKey()
    {
        // ManagerView.public_identity is a display label (bootstrap uses key:<hex>).
        // Binding uses top-level manager_public_key only.
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-11", NowPlus(3600), "alice", keyHex,
                        managerPublicIdentity: "key:" + keyHex,
                        mfaRequired: true, mfaAvailable: true)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-11", "ctok-11", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var login = await client.CompleteChallengeAsync(pending, "123456", CancellationToken.None);
            Assert.Equal(keyHex, login.ManagerPublicKey);
        }
    }

    [Fact]
    public async Task Complete_MfaMetadataInconsistent_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                // Required challenge completed, but response claims MFA required
                // without an available factor.
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-12", NowPlus(3600), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: false)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-12", "ctok-12", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, "123456", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        }
    }

    [Fact]
    public async Task Complete_PendingManager_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var json =
                    "{\"token\":\"tok-13\",\"expires_at_unix\":" + NowPlus(3600) +
                    ",\"account\":{\"id\":\"a\",\"username\":\"alice\",\"state\":\"active\"," +
                    "\"capabilities\":{},\"revision\":1}," +
                    "\"manager\":{\"id\":\"m\",\"public_identity\":\"p\",\"lifecycle_state\":\"pending\"}," +
                    "\"mfa\":{\"required\":true,\"available\":true}," +
                    "\"manager_public_key\":\"" + keyHex + "\"}";
                return TestHttpScripts.Json(json);
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-13", "ctok-13", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, "123456", CancellationToken.None));
            Assert.Equal(ServerClientFailure.Forbidden, ex.Failure);
        }
    }

    [Fact]
    public async Task Complete_SessionLongerThanTwoHours_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-14", NowPlus(3 * 60 * 60), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: true)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-14", "ctok-14", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, "123456", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task CancelledCompletion_DoesNotInstallLateSession()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var (server, client, _) = Start(pki, async (head, ct) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                try
                {
                    await gate.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
                }
                catch (OperationCanceledException)
                {
                    // Client cancelled; still try to finish late like a slow server.
                }

                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-late", NowPlus(3600), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: true)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-15", "ctok-15", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key, timeout: TimeSpan.FromSeconds(3));

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            using var cts = new CancellationTokenSource();
            var completeTask = client.CompleteChallengeAsync(pending, "123456", cts.Token);
            cts.Cancel();
            var ex = await Assert.ThrowsAsync<ServerClientException>(() => completeTask);
            Assert.Equal(ServerClientFailure.Cancelled, ex.Failure);
            gate.TrySetResult();
            await Task.Delay(50);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task Dispose_ClearsSessionAndPendingChallenge()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-16", NowPlus(3600), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: false, mfaAvailable: false)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-16", "ctok-16", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: false)),
                status: 201);
        }, key);

        await using (server)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            Assert.False(pending.IsCleared);
            client.Dispose();
            Assert.True(pending.IsCleared);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task Complete_DelayedResponse_WithServerTtl7200_IsAccepted()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, async (head, ct) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                // Network/password/device-proof work crosses a second boundary.
                await Task.Delay(TimeSpan.FromSeconds(1.2), ct);
                // Server TTL is a full 7200s from issue time at response build.
                var expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + AuthChallengeBounds.MaxSessionLifetimeSeconds;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-ttl", expires, "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: true)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-ttl", "ctok-ttl", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key, timeout: TimeSpan.FromSeconds(15));

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var login = await client.CompleteChallengeAsync(pending, "123456", CancellationToken.None);
            Assert.Equal("tok-ttl", login.Token);
            Assert.True(client.HasSession);
        }
    }

    [Fact]
    public async Task Complete_ReceptionRelativeLifetimeAbove7200_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, async (head, ct) =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                await Task.Delay(TimeSpan.FromSeconds(1.2), ct);
                // Remaining lifetime at reception still exceeds the hard bound.
                var expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    + AuthChallengeBounds.MaxSessionLifetimeSeconds
                    + 30;
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-big", expires, "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: true)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-big", "ctok-big", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key, timeout: TimeSpan.FromSeconds(15));

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, "123456", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
            Assert.False(client.HasSession);
        }
    }

    [Fact]
    public async Task Complete_ExpiredResponse_IsRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-exp", NowPlus(-2), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: true, mfaAvailable: true)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-exp", "ctok-exp", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: true)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, "123456", CancellationToken.None));
            Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        }
    }

    [Fact]
    public async Task Complete_Twice_SecondRefused()
    {
        using var pki = TestDeploymentPki.Create("HS V2 Auth CA");
        using var key = Ed25519DeviceKey.Create();
        var keyHex = key.PublicKeyHex;

        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                return TestHttpScripts.Json(
                    Encoding.UTF8.GetString(LoginJson(
                        "tok-17", NowPlus(3600), "alice", keyHex, $"key:{keyHex}",
                        mfaRequired: false, mfaAvailable: false)));
            }

            return TestHttpScripts.Json(
                Encoding.UTF8.GetString(BeginJson(
                    "chal-17", "ctok-17", "session", keyHex, TrustedDeployment,
                    NowPlus(90), mfaRequired: false)),
                status: 201);
        }, key);

        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "pw", CancellationToken.None);
            await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
            await Assert.ThrowsAsync<ServerClientException>(() =>
                client.CompleteChallengeAsync(pending, null, CancellationToken.None));
        }
    }
}
