using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
    private const long HistoricalUnix = 1_700_000_000;

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

    [Fact]
    public void VerifyEndpointChallenge_AcceptsSignedEndpointIdentityAndCertificate()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = GrantAt(HistoricalUnix, managerKey, endpointKey);
        var grant = VerifiedGrant(serverKey, fixture, HistoricalUnix);
        string nonce = CreateEndpointNonce("4a");
        byte[] certificate = CreateEndpointCertificate();
        string signature = SignEndpointCertificate(
            grant, certificate, nonce, endpointKey, HistoricalUnix);

        var challenge = ObservationEndpointChallenge.Verify(
            EndpointChallengeJson(
                fixture.ComputerId,
                fixture.EndpointSessionId,
                nonce,
                fixture.ExpiresAtUnix,
                Encoding.UTF8.GetString(certificate),
                signature),
            grant,
            At(HistoricalUnix));

        Assert.Equal(fixture.ComputerId, challenge.ComputerId);
        Assert.Equal(fixture.EndpointSessionId, challenge.EndpointSessionId);
        Assert.Equal(nonce, challenge.EndpointNonceHex);
        Assert.Equal(fixture.ExpiresAtUnix, challenge.ExpiresAtUnix);
        Assert.True(certificate.AsSpan().SequenceEqual(challenge.CopyEndpointCertificatePem()));
    }

    [Fact]
    public void VerifyEndpointChallenge_RejectsIdentityAndExpiryClaimMismatches()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = GrantAt(HistoricalUnix, managerKey, endpointKey);
        var grant = VerifiedGrant(serverKey, fixture, HistoricalUnix);
        string nonce = CreateEndpointNonce("4a");
        string uppercaseNonce = nonce.ToUpperInvariant();
        Assert.NotEqual(nonce, uppercaseNonce);
        string certificate = Encoding.UTF8.GetString(CreateEndpointCertificate());
        string signature = SignEndpointCertificate(
            grant, CreateEndpointCertificate(), nonce, endpointKey, HistoricalUnix);
        string validJson = EndpointChallengeJson(
            fixture.ComputerId,
            fixture.EndpointSessionId,
            nonce,
            fixture.ExpiresAtUnix,
            certificate,
            signature);

        var cases = new (string Name, string Json, long VerifyAtUnix)[]
        {
            ("different computer", EndpointChallengeJson(
                "00000000-0000-4000-8000-000000000002",
                fixture.EndpointSessionId,
                nonce,
                fixture.ExpiresAtUnix,
                certificate,
                signature), HistoricalUnix),
            ("different endpoint session", EndpointChallengeJson(
                fixture.ComputerId,
                "00000000-0000-4000-8000-000000000002",
                nonce,
                fixture.ExpiresAtUnix,
                certificate,
                signature), HistoricalUnix),
            ("malformed endpoint nonce", EndpointChallengeJson(
                fixture.ComputerId,
                fixture.EndpointSessionId,
                "not-lower-hex",
                fixture.ExpiresAtUnix,
                certificate,
                signature), HistoricalUnix),
            ("uppercase endpoint nonce", EndpointChallengeJson(
                fixture.ComputerId,
                fixture.EndpointSessionId,
                uppercaseNonce,
                fixture.ExpiresAtUnix,
                certificate,
                signature), HistoricalUnix),
            ("expiry earlier than grant", EndpointChallengeJson(
                fixture.ComputerId,
                fixture.EndpointSessionId,
                nonce,
                fixture.ExpiresAtUnix - 1,
                certificate,
                signature), HistoricalUnix),
            ("expiry later than grant", EndpointChallengeJson(
                fixture.ComputerId,
                fixture.EndpointSessionId,
                nonce,
                fixture.ExpiresAtUnix + 1,
                certificate,
                signature), HistoricalUnix),
            ("challenge expired at grant expiry", validJson, fixture.ExpiresAtUnix),
        };

        foreach (var (name, json, verifyAtUnix) in cases)
        {
            var exception = Record.Exception(() => ObservationEndpointChallenge.Verify(
                json,
                grant,
                At(verifyAtUnix)));
            AssertChallengeRejected(exception, name);
        }
    }

    [Fact]
    public void VerifyEndpointChallenge_RejectsCertificateAttestationSignatureMismatches()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        using var otherEndpointKey = Ed25519DeviceKey.Create();
        var fixture = GrantAt(HistoricalUnix, managerKey, endpointKey);
        var grant = VerifiedGrant(serverKey, fixture, HistoricalUnix);
        string nonce = CreateEndpointNonce("4a");
        string otherNonce = CreateEndpointNonce("5b");
        byte[] certificate = CreateEndpointCertificate();
        byte[] otherCertificate = Encoding.UTF8.GetBytes(
            "-----BEGIN CERTIFICATE-----\nBQYHCA==\n-----END CERTIFICATE-----\n");
        string certificateText = Encoding.UTF8.GetString(certificate);
        string validSignature = SignEndpointCertificate(
            grant, certificate, nonce, endpointKey, HistoricalUnix);
        string signatureForOtherNonce = SignEndpointCertificate(
            grant, certificate, otherNonce, endpointKey, HistoricalUnix);
        string signatureForOtherCertificate = SignEndpointCertificate(
            grant, otherCertificate, nonce, endpointKey, HistoricalUnix);
        string managerSignature = SignEndpointCertificate(
            grant, certificate, nonce, managerKey, HistoricalUnix);
        string uppercaseSignature = UppercaseFirstHexLetter(validSignature);
        Assert.Equal(validSignature.Length, uppercaseSignature.Length);
        Assert.Contains(uppercaseSignature, static character => character is >= 'A' and <= 'F');

        var cases = new (string Name, string Signature)[]
        {
            ("signed by another endpoint key", SignEndpointCertificate(
                grant, certificate, nonce, otherEndpointKey, HistoricalUnix)),
            ("signature made for another nonce", signatureForOtherNonce),
            ("signature made for another certificate", signatureForOtherCertificate),
            ("manager key used for endpoint role", managerSignature),
            ("uppercase signature", uppercaseSignature),
            ("truncated signature", validSignature[..^2]),
            ("empty signature", string.Empty),
        };

        foreach (var (name, signature) in cases)
        {
            string json = EndpointChallengeJson(
                fixture.ComputerId,
                fixture.EndpointSessionId,
                nonce,
                fixture.ExpiresAtUnix,
                certificateText,
                signature);
            var exception = Record.Exception(() => ObservationEndpointChallenge.Verify(
                json,
                grant,
                At(HistoricalUnix)));
            AssertChallengeRejected(exception, name);
        }
    }

    [Fact]
    public void VerifyEndpointChallenge_RejectsAttestationMadeForAnotherGrant()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var firstFixture = GrantAt(HistoricalUnix, managerKey, endpointKey);
        var secondFixture = firstFixture with
        {
            GrantId = "c14aed02-2397-4d25-9029-2e2c4e39b338",
        };
        var firstGrant = VerifiedGrant(serverKey, firstFixture, HistoricalUnix);
        var secondGrant = VerifiedGrant(serverKey, secondFixture, HistoricalUnix);
        string nonce = CreateEndpointNonce("4a");
        byte[] certificate = CreateEndpointCertificate();
        string signatureForFirstGrant = SignEndpointCertificate(
            firstGrant, certificate, nonce, endpointKey, HistoricalUnix);

        var exception = Record.Exception(() => ObservationEndpointChallenge.Verify(
            EndpointChallengeJson(
                secondFixture.ComputerId,
                secondFixture.EndpointSessionId,
                nonce,
                secondFixture.ExpiresAtUnix,
                Encoding.UTF8.GetString(certificate),
                signatureForFirstGrant),
            secondGrant,
            At(HistoricalUnix)));

        AssertChallengeRejected(exception, "replayed challenge signature across grants");
    }

    [Fact]
    public void VerifyEndpointChallenge_RejectsServerCompatibleChallengeWithoutAttestation()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = GrantAt(HistoricalUnix, managerKey, endpointKey);
        var grant = VerifiedGrant(serverKey, fixture, HistoricalUnix);
        // The deployment server treats this four-claim form as compatible;
        // the Manager requires the certificate attestation to pin the peer.
        string json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["computer_id"] = fixture.ComputerId,
            ["endpoint_session_id"] = fixture.EndpointSessionId,
            ["endpoint_nonce"] = CreateEndpointNonce("4a"),
            ["expires_at_unix"] = fixture.ExpiresAtUnix,
        });

        var exception = Record.Exception(() => ObservationEndpointChallenge.Verify(
            json,
            grant,
            At(HistoricalUnix)));

        AssertChallengeRejected(exception, "server-compatible omission without attestation");
    }

    [Fact]
    public void VerifyEndpointChallenge_RejectsMalformedOrUnsupportedClaims()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = GrantAt(HistoricalUnix, managerKey, endpointKey);
        var grant = VerifiedGrant(serverKey, fixture, HistoricalUnix);
        string nonce = CreateEndpointNonce("4a");
        string certificate = Encoding.UTF8.GetString(CreateEndpointCertificate());
        string signature = SignEndpointCertificate(
            grant, CreateEndpointCertificate(), nonce, endpointKey, HistoricalUnix);
        string validJson = EndpointChallengeJson(
            fixture.ComputerId,
            fixture.EndpointSessionId,
            nonce,
            fixture.ExpiresAtUnix,
            certificate,
            signature);
        string expiresClaim = $"\"expires_at_unix\":{fixture.ExpiresAtUnix}";
        string certificateClaim = $"\"endpoint_certificate_pem\":{JsonSerializer.Serialize(certificate)}";
        string signatureClaim = $"\"endpoint_certificate_signature\":{JsonSerializer.Serialize(signature)}";

        var cases = new (string Name, string Json)[]
        {
            ("empty payload", string.Empty),
            ("non-object payload", "[]"),
            ("oversized payload", new string(' ', 4097)),
            ("non-ASCII payload", "{\"computer_id\":\"é\"}"),
            ("extra claim", validJson.Insert(validJson.Length - 1, ",\"extra\":true")),
            ("duplicate claim", validJson.Insert(
                validJson.Length - 1,
                $",\"computer_id\":\"{fixture.ComputerId}\"")),
            ("missing computer claim", validJson.Replace(
                $"\"computer_id\":\"{fixture.ComputerId}\",", string.Empty)),
            ("missing certificate claim", validJson.Replace(certificateClaim + ",", string.Empty)),
            ("null certificate claim", validJson.Replace(
                certificateClaim, "\"endpoint_certificate_pem\":null")),
            ("missing certificate signature claim", validJson.Replace(
                "," + signatureClaim, string.Empty)),
            ("string expiry claim", validJson.Replace(
                expiresClaim,
                $"\"expires_at_unix\":\"{fixture.ExpiresAtUnix}\"")),
            ("fractional expiry claim", validJson.Replace(
                expiresClaim,
                $"\"expires_at_unix\":{fixture.ExpiresAtUnix}.0")),
            ("trailing comma", validJson.Insert(validJson.Length - 1, ",")),
            ("malformed certificate", EndpointChallengeJson(
                fixture.ComputerId,
                fixture.EndpointSessionId,
                nonce,
                fixture.ExpiresAtUnix,
                "not a certificate",
                signature)),
        };

        foreach (var (name, json) in cases)
        {
            var exception = Record.Exception(() => ObservationEndpointChallenge.Verify(
                json,
                grant,
                At(HistoricalUnix)));
            AssertChallengeRejected(exception, name);
        }
    }

    [Fact]
    public void PeerCertificateAttestation_UsesExplicitInstant_WhilePublicOverloadStaysLive()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        var fixture = GrantAt(HistoricalUnix, managerKey, endpointKey);
        var grant = VerifiedGrant(serverKey, fixture, HistoricalUnix);
        string nonce = CreateEndpointNonce("4a");
        byte[] certificate = CreateEndpointCertificate();
        byte[] message = grant.CreatePeerCertificateAttestationMessage(
            certificate, nonce, ObservationPeerRole.Endpoint, HistoricalUnix);
        byte[] signature = endpointKey.Sign(message);
        try
        {
            string signatureHex = Ed25519DeviceKey.ToLowerHex(signature);
            Assert.True(grant.VerifyPeerCertificateAttestation(
                certificate, nonce, ObservationPeerRole.Endpoint, signatureHex, HistoricalUnix));
            Assert.False(grant.VerifyPeerCertificateAttestation(
                certificate, nonce, ObservationPeerRole.Endpoint, signatureHex,
                fixture.ExpiresAtUnix));

            // Public endpoint-facing overloads keep live-clock expiry semantics.
            Assert.False(grant.VerifyPeerCertificateAttestation(
                certificate, nonce, ObservationPeerRole.Endpoint, signatureHex));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static GrantFixture GrantAt(
        long nowUnix,
        Ed25519DeviceKey managerKey,
        Ed25519DeviceKey endpointKey) =>
        ValidGrant(managerKey, endpointKey) with
        {
            IssuedAtUnix = nowUnix - 1,
            ExpiresAtUnix = nowUnix + 9,
        };

    private static VerifiedObservationAdmissionGrant VerifiedGrant(
        Ed25519DeviceKey serverKey,
        GrantFixture fixture,
        long nowUnix) =>
        ObservationAdmissionGrantVerifier.VerifyForManager(
            CreateToken(serverKey, CanonicalJson(fixture)),
            serverKey.PublicKeyHex,
            ManagerContext(fixture),
            At(nowUnix));

    private static byte[] CreateEndpointCertificate() =>
        Encoding.UTF8.GetBytes(
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n");

    private static string CreateEndpointNonce(string pair) =>
        string.Concat(Enumerable.Repeat(pair, 32));

    private static string SignEndpointCertificate(
        VerifiedObservationAdmissionGrant grant,
        byte[] certificatePem,
        string endpointNonceHex,
        Ed25519DeviceKey signingKey,
        long nowUnix)
    {
        byte[] message = grant.CreatePeerCertificateAttestationMessage(
            certificatePem,
            endpointNonceHex,
            ObservationPeerRole.Endpoint,
            nowUnix);
        byte[] signature = signingKey.Sign(message);
        try
        {
            return Ed25519DeviceKey.ToLowerHex(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static string UppercaseFirstHexLetter(string signature)
    {
        char[] characters = signature.ToCharArray();
        for (int index = 0; index < characters.Length; index++)
        {
            if (characters[index] is >= 'a' and <= 'f')
            {
                characters[index] = (char)(characters[index] - 'a' + 'A');
                return new string(characters);
            }
        }

        // A digit-only signature still cannot pass the lowercase-hex gate when
        // one digit is replaced with an uppercase letter.
        characters[0] = 'A';
        return new string(characters);
    }

    private static string EndpointChallengeJson(
        string computerId,
        string endpointSessionId,
        string endpointNonce,
        long expiresAtUnix,
        string certificatePem,
        string certificateSignature) =>
        JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["computer_id"] = computerId,
            ["endpoint_session_id"] = endpointSessionId,
            ["endpoint_nonce"] = endpointNonce,
            ["expires_at_unix"] = expiresAtUnix,
            ["endpoint_certificate_pem"] = certificatePem,
            ["endpoint_certificate_signature"] = certificateSignature,
        });

    private static void AssertChallengeRejected(Exception? exception, string caseName)
    {
        if (exception is not ServerClientException serverException)
        {
            throw new Xunit.Sdk.XunitException(
                $"{caseName}: expected an invalid-response ServerClientException, got " +
                (exception?.GetType().Name ?? "no exception") + ".");
        }
        Assert.Equal(ServerClientFailure.InvalidResponse, serverException.Failure);
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
