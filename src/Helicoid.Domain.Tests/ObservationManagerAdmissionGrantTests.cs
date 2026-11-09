using System.Text;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

public sealed class ObservationManagerAdmissionGrantTests
{
    private const string DeploymentId = "dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string AccountId = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d";
    private const string ManagerId = "7a01cf88-6fdb-4cc1-a72f-d155f5309355";
    private const string ComputerId = "e475b9ca-801a-4f71-b5d5-b87daaaae731";
    private const string EndpointSessionId = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1";
    private const string GrantId = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173";
    private const long NowUnix = 1_800_000_000;

    [Fact]
    public void VerifyForManager_AcceptsSignedGrant_AndReturnsSignedEndpointClaims()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);
        var token = CreateToken(serverKey, CanonicalJson(fixture));

        var verified = ObservationAdmissionGrantVerifier.VerifyForManager(
            token,
            serverKey.PublicKeyHex,
            ManagerContext(fixture),
            At(NowUnix));

        Assert.Equal(fixture.GrantId, verified.GrantId);
        Assert.Equal(fixture.DeploymentId, verified.DeploymentId);
        Assert.Equal(fixture.AccountId, verified.AccountId);
        Assert.Equal(fixture.ManagerId, verified.ManagerId);
        Assert.Equal(fixture.ComputerId, verified.ComputerId);
        Assert.Equal(fixture.EndpointPublicKey, verified.EndpointPublicKeyHex);
        Assert.Equal(fixture.EndpointSessionId, verified.EndpointSessionId);
        Assert.Equal(fixture.EnrollmentEpoch, verified.EnrollmentEpoch);
        Assert.Equal(fixture.IssuedAtUnix, verified.IssuedAtUnix);
        Assert.Equal(fixture.ExpiresAtUnix, verified.ExpiresAtUnix);
    }

    [Fact]
    public void VerifyForManager_DoesNotRequireEndpointContext_AndTrustsOnlySignedEndpointClaims()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey) with
        {
            EndpointSessionId = "c14aed02-2397-4d25-9029-2e2c4e39b338",
            EnrollmentEpoch = 17,
        };
        var token = CreateToken(serverKey, CanonicalJson(fixture));

        var verified = ObservationAdmissionGrantVerifier.VerifyForManager(
            token,
            serverKey.PublicKeyHex,
            ManagerContext(fixture),
            At(NowUnix));

        Assert.Equal(fixture.EndpointPublicKey, verified.EndpointPublicKeyHex);
        Assert.Equal(fixture.EndpointSessionId, verified.EndpointSessionId);
        Assert.Equal(17L, verified.EnrollmentEpoch);
    }

    [Fact]
    public void VerifyForManager_RejectsGrantForDifferentAccount()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);

        AssertManagerRejects(
            CreateToken(serverKey, CanonicalJson(fixture)),
            serverKey.PublicKeyHex,
            ManagerContext(fixture) with { AccountId = "00000000-0000-4000-8000-000000000001" });
    }

    [Fact]
    public void VerifyForManager_RejectsGrantForDifferentComputer()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);

        AssertManagerRejects(
            CreateToken(serverKey, CanonicalJson(fixture)),
            serverKey.PublicKeyHex,
            ManagerContext(fixture) with { ComputerId = "00000000-0000-4000-8000-000000000002" });
    }

    [Fact]
    public void VerifyForManager_RejectsGrantForDifferentManagerIdentity()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);

        AssertManagerRejects(
            CreateToken(serverKey, CanonicalJson(fixture)),
            serverKey.PublicKeyHex,
            ManagerContext(fixture) with { ManagerId = "00000000-0000-4000-8000-000000000003" });
    }

    [Fact]
    public void VerifyForManager_RejectsGrantForDifferentManagerKey()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var otherManagerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);

        AssertManagerRejects(
            CreateToken(serverKey, CanonicalJson(fixture)),
            serverKey.PublicKeyHex,
            ManagerContext(fixture) with { ManagerPublicKeyHex = otherManagerKey.PublicKeyHex });
    }

    [Fact]
    public void VerifyForManager_RejectsGrantForDifferentDeployment()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);

        AssertManagerRejects(
            CreateToken(serverKey, CanonicalJson(fixture)),
            serverKey.PublicKeyHex,
            ManagerContext(fixture) with
            {
                DeploymentId = "dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            });
    }

    [Fact]
    public void VerifyForManager_RejectsGrantSignedByDifferentServerKey()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var otherServerKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);

        AssertManagerRejects(
            CreateToken(otherServerKey, CanonicalJson(fixture)),
            serverKey.PublicKeyHex,
            ManagerContext(fixture));
    }

    [Fact]
    public void VerifyForManager_RejectsExpiredAndStaleGrants()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var valid = ValidGrant(managerKey, endpointKey);
        var expected = ManagerContext(valid);

        var cases = new (string Name, GrantFixture Fixture)[]
        {
            ("expired", valid with { IssuedAtUnix = NowUnix - 5, ExpiresAtUnix = NowUnix }),
            ("issued in the future", valid with { IssuedAtUnix = NowUnix + 6, ExpiresAtUnix = NowUnix + 9 }),
            ("expiry not after issue", valid with { IssuedAtUnix = NowUnix + 5, ExpiresAtUnix = NowUnix + 5 }),
            ("lifetime over ten seconds", valid with { IssuedAtUnix = NowUnix - 1, ExpiresAtUnix = NowUnix + 10 }),
        };

        foreach (var (name, fixture) in cases)
        {
            var exception = Record.Exception(() => ObservationAdmissionGrantVerifier.VerifyForManager(
                CreateToken(serverKey, CanonicalJson(fixture)),
                serverKey.PublicKeyHex,
                expected,
                At(NowUnix)));
            AssertUnauthorized(exception, name);
        }
    }

    [Fact]
    public void VerifyForManager_RejectsMalformedTokenEncoding()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);
        var expected = ManagerContext(fixture);
        var validToken = CreateToken(serverKey, CanonicalJson(fixture));
        int separator = validToken.IndexOf('.');
        string encodedPayload = validToken[..separator];
        string signature = validToken[(separator + 1)..];

        var malformed = new (string Name, string Token)[]
        {
            ("empty", string.Empty),
            ("empty payload", "." + signature),
            ("empty signed payload", CreateToken(serverKey, string.Empty)),
            ("empty payload and signature", "."),
            ("no separator", encodedPayload),
            ("empty signature", encodedPayload + "."),
            ("extra separator", validToken + ".extra"),
            ("uppercase signature", encodedPayload + "." + signature[..^1] + "A"),
            ("short signature", encodedPayload + "." + signature[..^2]),
            ("invalid base64url", "***." + signature),
            ("padded base64url", encodedPayload + "=." + signature),
            ("non-ASCII token", "\u00e9" + validToken),
            ("oversized token", new string('a', 8 * 1024 + 1) + "." + signature),
        };

        foreach (var (name, token) in malformed)
        {
            var exception = Record.Exception(() => ObservationAdmissionGrantVerifier.VerifyForManager(
                token,
                serverKey.PublicKeyHex,
                expected,
                At(NowUnix)));
            AssertUnauthorized(exception, name);
        }
    }

    [Fact]
    public void VerifyForManager_RejectsNoncanonicalOrUnsupportedClaims()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var valid = ValidGrant(managerKey, endpointKey);
        var expected = ManagerContext(valid);
        string canonical = CanonicalJson(valid);
        string issuedClaim = $"\"issued_at_unix\":{valid.IssuedAtUnix}";
        string expiresClaim = $"\"expires_at_unix\":{valid.ExpiresAtUnix}";
        string reordered = canonical.Replace(
            issuedClaim + "," + expiresClaim,
            expiresClaim + "," + issuedClaim);

        var signedPayloads = new (string Name, string Payload)[]
        {
            ("trailing whitespace", canonical + " "),
            ("duplicate claim key", canonical.Insert(
                canonical.Length - 1,
                ",\"grant_id\":\"" + GrantId + "\"")),
            ("escaped property name", canonical.Replace("\"grant_id\"", "\"grant\\u005fid\"")),
            ("escaped claim value", canonical.Replace(
                DeploymentId,
                "dep_\\u0061" + new string('a', 31))),
            ("reordered claims", reordered),
            ("noncanonical version number", canonical.Replace(
                "\"version\":1",
                "\"version\":1.0")),
            ("noncanonical epoch number", canonical.Replace(
                $"\"enrollment_epoch\":{valid.EnrollmentEpoch}",
                $"\"enrollment_epoch\":{valid.EnrollmentEpoch}.0")),
            ("extra claim", canonical.Insert(canonical.Length - 1, ",\"extra\":true")),
            ("missing claim", canonical.Replace(",\"capability\":\"observe\"", string.Empty)),
            ("wrong capability", CanonicalJson(valid with { Capability = "control" })),
            ("wrong version", CanonicalJson(valid with { Version = 2 })),
            ("uppercase endpoint key", CanonicalJson(valid with
            {
                EndpointPublicKey = endpointKey.PublicKeyHex.ToUpperInvariant(),
            })),
            ("uppercase manager key", CanonicalJson(valid with
            {
                ManagerPublicKey = managerKey.PublicKeyHex.ToUpperInvariant(),
            })),
            ("zero enrollment epoch", CanonicalJson(valid with { EnrollmentEpoch = 0 })),
            ("malformed endpoint session", CanonicalJson(valid with
            {
                EndpointSessionId = "not-a-guid",
            })),
            ("malformed grant id", CanonicalJson(valid with { GrantId = "not-a-guid" })),
            ("malformed deployment id", CanonicalJson(valid with
            {
                DeploymentId = "dep_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            })),
        };

        foreach (var (name, payload) in signedPayloads)
        {
            var exception = Record.Exception(() => ObservationAdmissionGrantVerifier.VerifyForManager(
                CreateToken(serverKey, payload),
                serverKey.PublicKeyHex,
                expected,
                At(NowUnix)));
            AssertUnauthorized(exception, name);
        }
    }

    [Fact]
    public void VerifyForManager_RejectsTamperedSignedPayload()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);
        var token = CreateToken(serverKey, CanonicalJson(fixture));
        int separator = token.IndexOf('.');
        string encodedPayload = token[..separator];
        string tamperedPayload = (encodedPayload[0] == 'e' ? 'f' : 'e') + encodedPayload[1..];

        var exception = Record.Exception(() => ObservationAdmissionGrantVerifier.VerifyForManager(
            tamperedPayload + token[separator..],
            serverKey.PublicKeyHex,
            ManagerContext(fixture),
            At(NowUnix)));
        AssertUnauthorized(exception);
    }

    [Fact]
    public void VerifyForManager_RejectsMalformedExpectedContext()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = ValidGrant(managerKey, endpointKey);
        var token = CreateToken(serverKey, CanonicalJson(fixture));

        var contexts = new ObservationAdmissionManager[]
        {
            ManagerContext(fixture) with { AccountId = AccountId.ToUpperInvariant() },
            ManagerContext(fixture) with { ComputerId = ComputerId.ToUpperInvariant() },
            ManagerContext(fixture) with { ManagerId = "not-a-guid" },
            ManagerContext(fixture) with { DeploymentId = "dep_short" },
            ManagerContext(fixture) with { ManagerPublicKeyHex = managerKey.PublicKeyHex.ToUpperInvariant() },
        };

        foreach (var context in contexts)
        {
            var exception = Record.Exception(() => ObservationAdmissionGrantVerifier.VerifyForManager(
                token,
                serverKey.PublicKeyHex,
                context,
                At(NowUnix)));
            AssertUnauthorized(exception);
        }
    }

    private static GrantFixture ValidGrant(
        Ed25519DeviceKey managerKey,
        Ed25519DeviceKey endpointKey) =>
        new(
            GrantId,
            DeploymentId,
            AccountId,
            ManagerId,
            managerKey.PublicKeyHex,
            ComputerId,
            endpointKey.PublicKeyHex,
            EndpointSessionId,
            EnrollmentEpoch: 3,
            IssuedAtUnix: NowUnix - 1,
            ExpiresAtUnix: NowUnix + 9);

    private static ObservationAdmissionManager ManagerContext(GrantFixture fixture) =>
        new(
            fixture.DeploymentId,
            fixture.AccountId,
            fixture.ComputerId,
            fixture.ManagerId,
            fixture.ManagerPublicKey);

    private static DateTimeOffset At(long unixSeconds) =>
        DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

    private static void AssertManagerRejects(
        string token,
        string serverPublicKeyHex,
        ObservationAdmissionManager expected)
    {
        var exception = Record.Exception(() => ObservationAdmissionGrantVerifier.VerifyForManager(
            token,
            serverPublicKeyHex,
            expected,
            At(NowUnix)));
        AssertUnauthorized(exception);
    }

    private static void AssertUnauthorized(Exception? exception, string? caseName = null)
    {
        if (exception is not ServerClientException serverException)
        {
            throw new Xunit.Sdk.XunitException(
                $"{caseName ?? "case"}: expected an unauthorized ServerClientException, got " +
                (exception?.GetType().Name ?? "no exception") + ".");
        }
        Assert.Equal(ServerClientFailure.Unauthorized, serverException.Failure);
    }

    private static string CreateToken(Ed25519DeviceKey serverKey, string payloadJson)
    {
        var payload = Encoding.UTF8.GetBytes(payloadJson);
        var domain = Encoding.UTF8.GetBytes("hs-observation-grant-v1\0");
        var signedMessage = new byte[domain.Length + payload.Length];
        domain.CopyTo(signedMessage, 0);
        payload.CopyTo(signedMessage, domain.Length);
        var signature = serverKey.Sign(signedMessage);
        try
        {
            return Convert.ToBase64String(payload)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_') + "." + Ed25519DeviceKey.ToLowerHex(signature);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(payload);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(signedMessage);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static string CanonicalJson(GrantFixture fixture) =>
        FormattableString.Invariant(
            $"{{\"version\":{fixture.Version},\"grant_id\":\"{fixture.GrantId}\",\"deployment_id\":\"{fixture.DeploymentId}\",\"account_id\":\"{fixture.AccountId}\",\"manager_id\":\"{fixture.ManagerId}\",\"manager_public_key\":\"{fixture.ManagerPublicKey}\",\"computer_id\":\"{fixture.ComputerId}\",\"endpoint_public_key\":\"{fixture.EndpointPublicKey}\",\"endpoint_session_id\":\"{fixture.EndpointSessionId}\",\"enrollment_epoch\":{fixture.EnrollmentEpoch},\"issued_at_unix\":{fixture.IssuedAtUnix},\"expires_at_unix\":{fixture.ExpiresAtUnix},\"capability\":\"{fixture.Capability}\"}}");

    private sealed record GrantFixture(
        string GrantId,
        string DeploymentId,
        string AccountId,
        string ManagerId,
        string ManagerPublicKey,
        string ComputerId,
        string EndpointPublicKey,
        string EndpointSessionId,
        long EnrollmentEpoch,
        long IssuedAtUnix,
        long ExpiresAtUnix,
        string Capability = "observe",
        int Version = 1);
}
