using System.Net;
using System.Runtime.CompilerServices;
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

    // =====================================================================
    // Coordinator review regressions (actual pinned HTTPS + actual System
    // clock). Ported from the independent review snapshot without weakening.
    // =====================================================================

    [Fact]
    public async Task CoordinatorReview_ActualClockExpiry_DropsSessionWithoutAnotherRequest()
    {
        using var pki = TestDeploymentPki.Create("HS expiry review CA");
        using var key = Ed25519DeviceKey.Create();
        long expires = 0;
        int inventoryRequests = 0;
        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                expires = NowPlus(2);
                return TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-token-not-logged", expires, "alice", key.PublicKeyHex,
                    $"key:{key.PublicKeyHex}", false, false)), status: 200);
            }
            if (head.Contains("/inventory", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref inventoryRequests);
                return TestHttpScripts.Json("{\"computers\":[]}", status: 200);
            }
            return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                TrustedDeployment, NowPlus(90), false)), status: 201);
        }, key);
        await using (server)
        using (client)
        {
            var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
            await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
            Assert.True(client.HasSession);
            var remaining = DateTimeOffset.FromUnixTimeSeconds(expires) - DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds(150);
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining);
            Assert.False(client.HasSession);
            var error = await Assert.ThrowsAsync<ServerClientException>(
                () => client.GetInventoryAsync(CancellationToken.None));
            Assert.Equal(ServerClientFailure.NotConnected, error.Failure);
            Assert.Equal(0, Volatile.Read(ref inventoryRequests));
        }
    }

    [Fact]
    public async Task CoordinatorReview_DelayedExpiryCannotResetReplacementSignIn()
    {
        using var pki = TestDeploymentPki.Create("HS expiry race review CA");
        using var key = Ed25519DeviceKey.Create();
        var completions = 0;
        var (server, client, _) = Start(pki, head =>
        {
            if (head.Contains("/complete", StringComparison.Ordinal))
            {
                var n = Interlocked.Increment(ref completions);
                return TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session-" + n, NowPlus(n == 1 ? 2 : 3600), "alice",
                    key.PublicKeyHex, $"key:{key.PublicKeyHex}", false, false)), status: 200);
            }
            return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                "review-challenge-" + Volatile.Read(ref completions), "review-challenge-token", "session",
                key.PublicKeyHex, TrustedDeployment, NowPlus(90), false)), status: 201);
        }, key);
        using var release = new ManualResetEventSlim();
        var blocked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        client.SessionExpired += (_, _) => { blocked.TrySetResult(); release.Wait(TimeSpan.FromSeconds(8)); };
        using var coordinator = new V2SignInCoordinator(client) { Username = "alice" };
        client.SessionExpired += (_, _) => drained.TrySetResult();
        await using (server)
        using (client)
        {
            try
            {
                await coordinator.SignInAsync("review-password", CancellationToken.None);
                Assert.True(coordinator.IsSignedIn);
                await blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await coordinator.SignInAsync("review-password", CancellationToken.None);
                Assert.True(coordinator.IsSignedIn);
                release.Set();
                await drained.Task.WaitAsync(TimeSpan.FromSeconds(3));
                Assert.True(client.HasSession);
                Assert.True(coordinator.IsSignedIn);
            }
            finally { release.Set(); }
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference<V2DeviceKeyChallengeClient>> ReviewSignInAndAbandon(
        TestDeploymentPki pki, TestHttpsServer server, Ed25519DeviceKey key)
    {
        var client = new V2DeviceKeyChallengeClient(TrustFor(pki, server.Origin), key);
        var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
        return new WeakReference<V2DeviceKeyChallengeClient>(client);
    }

    [Fact]
    public async Task CoordinatorReview_DeadlineDoesNotRetainAbandonedClient()
    {
        using var pki = TestDeploymentPki.Create("HS lifetime review CA");
        using var key = Ed25519DeviceKey.Create();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session", NowPlus(3600), "alice", key.PublicKeyHex,
                    $"key:{key.PublicKeyHex}", false, false)), status: 200)
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201));
        var weak = await ReviewSignInAndAbandon(pki, server, key);
        for (var n = 0; n < 3; n++)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            await Task.Delay(30);
        }
        Assert.False(weak.TryGetTarget(out _));
    }

    [Fact]
    public async Task CoordinatorReview_ActualClockAutomaticallyClearsCoordinator()
    {
        using var pki = TestDeploymentPki.Create("HS automatic UI review CA");
        using var key = Ed25519DeviceKey.Create();
        var (server, client, _) = Start(pki, head => head.Contains("/complete", StringComparison.Ordinal)
            ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                "review-session", NowPlus(2), "alice", key.PublicKeyHex,
                $"key:{key.PublicKeyHex}", false, false)), status: 200)
            : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                TrustedDeployment, NowPlus(90), false)), status: 201), key);
        using var coordinator = new V2SignInCoordinator(client) { Username = "alice" };
        var expired = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        coordinator.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(V2SignInCoordinator.ManagerLifecycleState)
                && coordinator.Phase == V2SignInPhase.Ready
                && string.IsNullOrEmpty(coordinator.ManagerLifecycleState)
                && coordinator.StatusMessage.Contains("expired", StringComparison.OrdinalIgnoreCase))
                expired.TrySetResult();
        };
        await using (server)
        using (client)
        {
            await coordinator.SignInAsync("review-password", CancellationToken.None);
            Assert.True(coordinator.IsSignedIn);
            await expired.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(coordinator.IsSignedIn);
            Assert.False(client.HasSession);
            Assert.Empty(coordinator.SignedInAccountName);
            Assert.Empty(coordinator.ManagerLifecycleState);
        }
    }

    private sealed class ReviewEarlyClock(long frequency = TimeSpan.TicksPerSecond) : TimeProvider
    {
        private DateTimeOffset _utc = DateTimeOffset.UtcNow;
        private long _stamp;
        private readonly List<ReviewTimer> _timers = new();
        public override long TimestampFrequency => frequency;
        public TimeSpan LastScheduledDue { get; private set; }
        public int ActiveTimerCount => _timers.Count(t => t.Active);
        public override DateTimeOffset GetUtcNow() => _utc;
        private int _readsBeforeAdvance;
        private TimeSpan _advanceAtRead;
        public void AdvanceOnTimestampRead(int reads, TimeSpan delta) { _readsBeforeAdvance = reads; _advanceAtRead = delta; }
        public override long GetTimestamp()
        {
            if (_readsBeforeAdvance > 0 && --_readsBeforeAdvance == 0) AdvanceWithoutDispatch(_advanceAtRead);
            return _stamp;
        }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ReviewTimer(this, callback, state);
            _timers.Add(timer);
            timer.Change(dueTime, period);
            return timer;
        }
        public void FireEarly() => _timers.First(t => t.Active).Fire();
        public void AdvanceWithoutDispatch(TimeSpan delta)
        {
            _stamp += (long)((Int128)delta.Ticks * frequency / TimeSpan.TicksPerSecond);
            _utc += delta;
        }
        public void Advance(TimeSpan delta)
        {
            _stamp += (long)((Int128)delta.Ticks * frequency / TimeSpan.TicksPerSecond);
            _utc += delta;
            foreach (var timer in _timers.Where(t => t.Active && t.Due <= _stamp).ToArray()) timer.Fire();
        }
        private sealed class ReviewTimer(ReviewEarlyClock owner, TimerCallback callback, object? state) : ITimer
        {
            private bool _disposed;
            public long Due { get; private set; }
            public bool Active { get; private set; }
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                if (_disposed) return false;
                Active = dueTime != Timeout.InfiniteTimeSpan;
                owner.LastScheduledDue = dueTime;
                Due = owner._stamp + (long)((Int128)dueTime.Ticks * owner.TimestampFrequency / TimeSpan.TicksPerSecond);
                return true;
            }
            public void Fire() { Active = false; callback(state); }
            public void Dispose() { _disposed = true; Active = false; }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }

    [Fact]
    public async Task CoordinatorReview_EarlyCallbackRearmsAutomaticExpiry()
    {
        using var pki = TestDeploymentPki.Create("HS early timer review CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session", NowPlus(10), "alice", key.PublicKeyHex,
                    $"key:{key.PublicKeyHex}", false, false)), status: 200)
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201));
        using var client = new V2DeviceKeyChallengeClient(
            new PinnedHttpsTransport(TrustFor(pki, server.Origin)), key,
            TrustedDeployment, ownsTransport: true, timeProvider: clock);
        var notifications = 0;
        client.SessionExpired += (_, _) => Interlocked.Increment(ref notifications);
        var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
        clock.FireEarly();
        Assert.Equal(0, Volatile.Read(ref notifications));
        clock.Advance(TimeSpan.FromSeconds(11));
        // Observe the automatic signal before any lazy HasSession check.
        Assert.Equal(1, Volatile.Read(ref notifications));
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task CoordinatorReview_ExpiryBetweenCallbackChecksStillNotifies()
    {
        using var pki = TestDeploymentPki.Create("HS early timer review CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock();
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session", NowPlus(10), "alice", key.PublicKeyHex,
                    $"key:{key.PublicKeyHex}", false, false)), status: 200)
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201));
        using var client = new V2DeviceKeyChallengeClient(
            new PinnedHttpsTransport(TrustFor(pki, server.Origin)), key,
            TrustedDeployment, ownsTransport: true, timeProvider: clock);
        var notifications = 0;
        client.SessionExpired += (_, _) => Interlocked.Increment(ref notifications);
        var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
        // First expiry read is early; time crosses the deadline before the
        // callback's second expiry check, after its fired timer was detached.
        clock.AdvanceOnTimestampRead(2, TimeSpan.FromSeconds(11));
        clock.FireEarly();
        // Observe the automatic signal before any lazy HasSession check.
        Assert.Equal(1, Volatile.Read(ref notifications));
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task CoordinatorReview_DelayedExpiryCannotCancelReplacementMfaCompletion()
    {
        using var pki = TestDeploymentPki.Create("HS pending MFA race review CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock();
        var begins = 0;
        var completions = 0;
        var completionStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), async (head, ct) =>
            {
                if (head.Contains("/complete", StringComparison.Ordinal))
                {
                    var n = Interlocked.Increment(ref completions);
                    if (n == 2)
                    {
                        completionStarted.TrySetResult();
                        await releaseCompletion.Task.WaitAsync(ct);
                    }
                    return TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                        "review-session-" + n, NowPlus(n == 1 ? 2 : 3600), "alice", key.PublicKeyHex,
                        $"key:{key.PublicKeyHex}", n == 2, n == 2)), status: 200);
                }
                var attempt = Interlocked.Increment(ref begins);
                return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge-" + attempt, "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), attempt == 2)), status: 201);
            });
        using var client = new V2DeviceKeyChallengeClient(new PinnedHttpsTransport(TrustFor(pki, server.Origin)),
            key, TrustedDeployment, ownsTransport: true, timeProvider: clock);
        using var releaseExpiry = new ManualResetEventSlim();
        var blocked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        client.SessionExpired += (_, _) => { blocked.TrySetResult(); releaseExpiry.Wait(TimeSpan.FromSeconds(8)); };
        using var coordinator = new V2SignInCoordinator(client) { Username = "alice" };
        client.SessionExpired += (_, _) => drained.TrySetResult();
        Task? finishing = null;
        Task? firing = null;
        try
        {
            await coordinator.SignInAsync("review-password", CancellationToken.None);
            Assert.True(coordinator.IsSignedIn);
            firing = Task.Run(() => clock.Advance(TimeSpan.FromSeconds(3)));
            await blocked.Task.WaitAsync(TimeSpan.FromSeconds(3));
            await coordinator.SignInAsync("review-password", CancellationToken.None);
            Assert.Equal(V2SignInPhase.AwaitingTotp, coordinator.Phase);
            finishing = coordinator.CompleteWithTotpAsync("123456", CancellationToken.None);
            await completionStarted.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(V2SignInPhase.Completing, coordinator.Phase);
            releaseExpiry.Set();
            await drained.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(V2SignInPhase.Completing, coordinator.Phase);
            releaseCompletion.TrySetResult();
            await finishing.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.True(coordinator.IsSignedIn);
        }
        finally
        {
            releaseExpiry.Set(); releaseCompletion.TrySetResult();
            if (firing is not null) await firing.WaitAsync(TimeSpan.FromSeconds(3));
            if (finishing is not null)
            {
                try { await finishing.WaitAsync(TimeSpan.FromSeconds(3)); }
                catch (ServerClientException) { }
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CoordinatorReview_LateInventoryCannotOutliveRequestSession(bool replace)
    {
        using var pki = TestDeploymentPki.Create("HS review stale successful inventory CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock();
        int completions = 0;
        var received = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), async (head, ct) =>
            {
                if (head.Contains("/computers", StringComparison.Ordinal))
                {
                    received.TrySetResult();
                    await release.Task.WaitAsync(ct);
                    return TestHttpScripts.Json("{\"computers\":[]}");
                }
                if (head.Contains("/complete", StringComparison.Ordinal))
                {
                    var n = Interlocked.Increment(ref completions);
                    return TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                        "review-session-" + n, NowPlus(n == 1 ? 2 : 3600), "alice", key.PublicKeyHex,
                        $"key:{key.PublicKeyHex}", false, false)));
                }
                return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201);
            });
        using var client = new V2DeviceKeyChallengeClient(new PinnedHttpsTransport(TrustFor(pki, server.Origin)),
            key, TrustedDeployment, ownsTransport: true, timeProvider: clock);
        var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
        var inventory = client.GetInventoryAsync(CancellationToken.None);
        try
        {
            await received.Task.WaitAsync(TimeSpan.FromSeconds(3));
            if (replace)
            {
                var next = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
                await client.CompleteChallengeAsync(next, null, CancellationToken.None);
            }
            else
            {
                clock.Advance(TimeSpan.FromSeconds(3));
            }
            release.TrySetResult();
            await Assert.ThrowsAsync<ServerClientException>(() => inventory);
            Assert.Equal(replace, client.HasSession);
        }
        finally
        {
            release.TrySetResult();
            try { await inventory.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (ServerClientException) { }
        }
    }

    [Fact]
    public async Task CoordinatorReview_EarlyCallbackPreservesHighFrequencyLongDeadline()
    {
        using var pki = TestDeploymentPki.Create("HS early timer high-frequency review CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock(1_000_000_000);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session", NowPlus(3600), "alice", key.PublicKeyHex,
                    $"key:{key.PublicKeyHex}", false, false)))
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201));
        using var client = new V2DeviceKeyChallengeClient(new PinnedHttpsTransport(TrustFor(pki, server.Origin)),
            key, TrustedDeployment, ownsTransport: true, timeProvider: clock);
        var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
        var initialDue = clock.LastScheduledDue;
        Assert.True(initialDue > TimeSpan.FromMinutes(59));
        clock.FireEarly();
        Assert.InRange(clock.LastScheduledDue.Ticks, initialDue.Ticks - 1, initialDue.Ticks + 1);
    }

    private sealed class ReviewQueuedContext : SynchronizationContext
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<(SendOrPostCallback Callback, object? State)> _queue = new();
        public override void Post(SendOrPostCallback callback, object? state) => _queue.Enqueue((callback, state));
        public void Drain()
        {
            var previous = Current;
            SetSynchronizationContext(this);
            try { while (_queue.TryDequeue(out var item)) item.Callback(item.State); }
            finally { SetSynchronizationContext(previous); }
        }
    }

    [Fact]
    public async Task CoordinatorReview_QueuedExpiryCannotCarryInventoryIntoReplacementSession()
    {
        using var pki = TestDeploymentPki.Create("HS queued UI expiry review CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock();
        int completions = 0;
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session-" + Interlocked.Increment(ref completions), NowPlus(completions == 1 ? 2 : 3600), "alice", key.PublicKeyHex,
                    $"key:{key.PublicKeyHex}", false, false)))
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201));
        using var client = new V2DeviceKeyChallengeClient(new PinnedHttpsTransport(TrustFor(pki, server.Origin)),
            key, TrustedDeployment, ownsTransport: true, timeProvider: clock);
        using var coordinator = new V2SignInCoordinator(client) { Username = "alice" };
        var queue = new ReviewQueuedContext();
        var previous = SynchronizationContext.Current;
        Helicoid.Manager.ViewModels.MainViewModel main;
        SynchronizationContext.SetSynchronizationContext(queue);
        try { main = new Helicoid.Manager.ViewModels.MainViewModel(DevelopmentLaunchOptions.Parse(Array.Empty<string>()), coordinator); }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
        using (main)
        {
            await Task.Run(() => coordinator.SignInAsync("review-password", CancellationToken.None));
            queue.Drain();
            Assert.Equal(Helicoid.Manager.ViewModels.ConnectionUiState.SignedIn, main.Connection.State);
            var record = new Helicoid.Domain.Model.ComputerRecord(Helicoid.Domain.Model.ComputerId.Parse("review-pc"), "PC", Helicoid.Domain.Model.ComputerStatus.Online);
            main.ApplyServerInventory(new[] { record });
            main.SelectTile(record.Id, additive: false);
            Assert.Single(main.Tiles);
            await Task.Run(() => clock.Advance(TimeSpan.FromSeconds(3)));
            Assert.Equal(V2SignInPhase.Ready, coordinator.Phase);
            await Task.Run(() => coordinator.SignInAsync("review-password", CancellationToken.None));
            Assert.True(coordinator.IsSignedIn);
            queue.Drain();
            Assert.Equal(Helicoid.Manager.ViewModels.ConnectionUiState.SignedIn, main.Connection.State);
            Assert.Empty(main.Tiles);
            Assert.Equal(0, main.Overview.Selection.Count);
        }
    }

    [Fact]
    public async Task CoordinatorReview_QueuedLossPreservesFreshReplacementInventory()
    {
        using var pki = TestDeploymentPki.Create("HS queued UI expiry review CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock();
        int completions = 0;
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), head =>
            head.Contains("/complete", StringComparison.Ordinal)
                ? TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                    "review-session-" + Interlocked.Increment(ref completions), NowPlus(completions == 1 ? 2 : 3600), "alice", key.PublicKeyHex,
                    $"key:{key.PublicKeyHex}", false, false)))
                : TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201));
        using var client = new V2DeviceKeyChallengeClient(new PinnedHttpsTransport(TrustFor(pki, server.Origin)),
            key, TrustedDeployment, ownsTransport: true, timeProvider: clock);
        using var coordinator = new V2SignInCoordinator(client) { Username = "alice" };
        var queue = new ReviewQueuedContext();
        var previous = SynchronizationContext.Current;
        Helicoid.Manager.ViewModels.MainViewModel main;
        SynchronizationContext.SetSynchronizationContext(queue);
        try { main = new Helicoid.Manager.ViewModels.MainViewModel(DevelopmentLaunchOptions.Parse(Array.Empty<string>()), coordinator); }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
        using (main)
        {
            await Task.Run(() => coordinator.SignInAsync("review-password", CancellationToken.None));
            queue.Drain();
            Assert.Equal(Helicoid.Manager.ViewModels.ConnectionUiState.SignedIn, main.Connection.State);
            var record = new Helicoid.Domain.Model.ComputerRecord(Helicoid.Domain.Model.ComputerId.Parse("review-pc"), "PC", Helicoid.Domain.Model.ComputerStatus.Online);
            main.ApplyServerInventory(new[] { record });
            main.SelectTile(record.Id, additive: false);
            Assert.Single(main.Tiles);
            await Task.Run(() => clock.Advance(TimeSpan.FromSeconds(3)));
            Assert.Equal(V2SignInPhase.Ready, coordinator.Phase);
            await Task.Run(() => coordinator.SignInAsync("review-password", CancellationToken.None));
            Assert.True(coordinator.IsSignedIn);
            var fresh = new Helicoid.Domain.Model.ComputerRecord(Helicoid.Domain.Model.ComputerId.Parse("review-fresh-pc"), "Fresh PC", Helicoid.Domain.Model.ComputerStatus.Online);
            main.ApplyServerInventory(new[] { fresh });
            queue.Drain();
            Assert.Equal(Helicoid.Manager.ViewModels.ConnectionUiState.SignedIn, main.Connection.State);
            Assert.Single(main.Tiles);
            Assert.Equal(fresh.Id, main.Tiles[0].Id);
            Assert.Equal(0, main.Overview.Selection.Count);
        }
    }

    [Fact]
    public async Task CoordinatorReview_DelayedTimerDispatchCannotPermitLateInventoryBody()
    {
        using var pki = TestDeploymentPki.Create("HS review stale successful inventory CA");
        using var key = Ed25519DeviceKey.Create();
        var clock = new ReviewEarlyClock();
        int completions = 0;
        var received = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = TestHttpsServer.Start(
            pki.CreateLeaf(dnsName: null, ipAddress: IPAddress.Loopback), async (head, ct) =>
            {
                if (head.Contains("/computers", StringComparison.Ordinal))
                {
                    received.TrySetResult();
                    await release.Task.WaitAsync(ct);
                    return TestHttpScripts.Json("{\"computers\":[]}");
                }
                if (head.Contains("/complete", StringComparison.Ordinal))
                {
                    var n = Interlocked.Increment(ref completions);
                    return TestHttpScripts.Json(Encoding.UTF8.GetString(LoginJson(
                        "review-session-" + n, NowPlus(n == 1 ? 2 : 3600), "alice", key.PublicKeyHex,
                        $"key:{key.PublicKeyHex}", false, false)));
                }
                return TestHttpScripts.Json(Encoding.UTF8.GetString(BeginJson(
                    "review-challenge", "review-challenge-token", "session", key.PublicKeyHex,
                    TrustedDeployment, NowPlus(90), false)), status: 201);
            });
        using var client = new V2DeviceKeyChallengeClient(new PinnedHttpsTransport(TrustFor(pki, server.Origin)),
            key, TrustedDeployment, ownsTransport: true, timeProvider: clock);
        var pending = await client.BeginChallengeAsync("alice", "review-password", CancellationToken.None);
        await client.CompleteChallengeAsync(pending, null, CancellationToken.None);
        var inventory = client.GetInventoryAsync(CancellationToken.None);
        try
        {
            await received.Task.WaitAsync(TimeSpan.FromSeconds(3));
            clock.AdvanceWithoutDispatch(TimeSpan.FromSeconds(3));
            release.TrySetResult();
            await Assert.ThrowsAsync<ServerClientException>(() => inventory);
            Assert.Equal(0, clock.ActiveTimerCount);
            Assert.False(client.HasSession);
        }
        finally
        {
            release.TrySetResult();
            try { await inventory.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (ServerClientException) { }
        }
    }
}
