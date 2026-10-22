using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Helicoid.Domain.Client;

/// <summary>Device whose ephemeral WebRTC certificate is being attested.</summary>
public enum ObservationPeerRole
{
    Manager,
    Endpoint,
}

/// <summary>Current endpoint identity expected in a server-signed observation grant.</summary>
public sealed record ObservationAdmissionEndpoint(
    string DeploymentId,
    string ComputerId,
    string EndpointPublicKeyHex,
    string EndpointSessionId,
    long EnrollmentEpoch);

/// <summary>A verified, endpoint-bound observation grant.</summary>
public sealed class VerifiedObservationAdmissionGrant
{
    private readonly string _managerPublicKeyHex;

    internal VerifiedObservationAdmissionGrant(ObservationAdmissionGrantVerifier.Claims claims)
    {
        GrantId = claims.GrantId;
        DeploymentId = claims.DeploymentId;
        AccountId = claims.AccountId;
        ManagerId = claims.ManagerId;
        _managerPublicKeyHex = claims.ManagerPublicKey;
        ComputerId = claims.ComputerId;
        EndpointPublicKeyHex = claims.EndpointPublicKey;
        EndpointSessionId = claims.EndpointSessionId;
        EnrollmentEpoch = claims.EnrollmentEpoch;
        IssuedAtUnix = claims.IssuedAtUnix;
        ExpiresAtUnix = claims.ExpiresAtUnix;
    }

    public string GrantId { get; }
    public string DeploymentId { get; }
    public string AccountId { get; }
    public string ManagerId { get; }
    public string ComputerId { get; }
    public string EndpointPublicKeyHex { get; }
    public string EndpointSessionId { get; }
    public long EnrollmentEpoch { get; }
    public long IssuedAtUnix { get; }
    public long ExpiresAtUnix { get; }

    /// <summary>Exact UTF-8 bytes the approved Manager signs for this nonce and verified channel.</summary>
    public byte[] CreateManagerProofMessage(string endpointNonceHex, string channelBindingHex)
    {
        ArgumentNullException.ThrowIfNull(endpointNonceHex);
        ArgumentNullException.ThrowIfNull(channelBindingHex);
        if (!ObservationAdmissionGrantVerifier.IsLowerHex(endpointNonceHex, 32))
        {
            throw ObservationAdmissionGrantVerifier.InvalidGrant();
        }
        if (!ObservationAdmissionGrantVerifier.IsCanonicalChannelBindingHex(channelBindingHex))
        {
            throw ObservationAdmissionGrantVerifier.InvalidGrant();
        }

        string message =
            $"hs-observation-peer-proof-v2|deployment:{DeploymentId}|grant:{GrantId}|computer:{ComputerId}|endpoint_session:{EndpointSessionId}|epoch:{EnrollmentEpoch}|nonce:{endpointNonceHex}|channel_binding:{channelBindingHex}";
        return Encoding.UTF8.GetBytes(message);
    }

    /// <summary>Verify the Manager proof locally before submitting redemption.</summary>
    public bool VerifyManagerProof(
        string endpointNonceHex,
        string channelBindingHex,
        string managerProofHex)
    {
        ArgumentNullException.ThrowIfNull(endpointNonceHex);
        ArgumentNullException.ThrowIfNull(managerProofHex);
        if (!ObservationAdmissionGrantVerifier.IsLowerHex(managerProofHex, 64))
        {
            return false;
        }

        byte[] message;
        byte[] signature;
        try
        {
            message = CreateManagerProofMessage(endpointNonceHex, channelBindingHex);
            signature = Convert.FromHexString(managerProofHex);
        }
        catch (ServerClientException)
        {
            return false;
        }

        try
        {
            return Ed25519DeviceKey.VerifyHex(
                _managerPublicKeyHex,
                message,
                signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    /// <summary>
    /// Build the canonical device-key statement for one exact ephemeral DTLS
    /// certificate. The nonce, role, and grant context prevent reuse across
    /// observations or peer directions.
    /// </summary>
    public byte[] CreatePeerCertificateAttestationMessage(
        ReadOnlySpan<byte> certificatePem,
        string endpointNonceHex,
        ObservationPeerRole role)
    {
        ArgumentNullException.ThrowIfNull(endpointNonceHex);
        if (!ObservationAdmissionGrantVerifier.IsLowerHex(endpointNonceHex, 32) ||
            ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() ||
            !ObservationAdmissionGrantVerifier.IsCertificatePem(certificatePem))
        {
            throw ObservationAdmissionGrantVerifier.InvalidGrant();
        }

        string roleText = role switch
        {
            ObservationPeerRole.Manager => "manager",
            ObservationPeerRole.Endpoint => "endpoint",
            _ => throw ObservationAdmissionGrantVerifier.InvalidGrant(),
        };
        byte[] certificateDigest = SHA256.HashData(certificatePem);
        try
        {
            string message =
                $"hs-observation-peer-certificate-v1|deployment:{DeploymentId}|grant:{GrantId}|computer:{ComputerId}|endpoint_session:{EndpointSessionId}|epoch:{EnrollmentEpoch}|nonce:{endpointNonceHex}|role:{roleText}|certificate_sha256:{Convert.ToHexString(certificateDigest).ToLowerInvariant()}";
            return Encoding.UTF8.GetBytes(message);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(certificateDigest);
        }
    }

    /// <summary>Verify the endpoint's certificate attestation before pinning its certificate.</summary>
    public bool VerifyPeerCertificateAttestation(
        ReadOnlySpan<byte> certificatePem,
        string endpointNonceHex,
        ObservationPeerRole role,
        string signatureHex)
    {
        ArgumentNullException.ThrowIfNull(signatureHex);
        string publicKeyHex = role switch
        {
            ObservationPeerRole.Manager => _managerPublicKeyHex,
            ObservationPeerRole.Endpoint => EndpointPublicKeyHex,
            _ => string.Empty,
        };
        if (publicKeyHex.Length == 0 || !ObservationAdmissionGrantVerifier.IsLowerHex(signatureHex, 64))
        {
            return false;
        }

        byte[] message;
        byte[] signature;
        try
        {
            message = CreatePeerCertificateAttestationMessage(certificatePem, endpointNonceHex, role);
            signature = Convert.FromHexString(signatureHex);
        }
        catch (ServerClientException)
        {
            return false;
        }

        try
        {
            return Ed25519DeviceKey.VerifyHex(publicKeyHex, message, signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(signature);
        }
    }
}

/// <summary>
/// Strict verifier for the server's version-1 observation admission token.
/// The server verification key must already be trusted through pinned HTTPS.
/// </summary>
public static class ObservationAdmissionGrantVerifier
{
    private static readonly byte[] Domain = Encoding.UTF8.GetBytes("hs-observation-grant-v1\0");
    private const int MaximumTokenBytes = 8 * 1024;
    private const int MaximumPayloadBytes = 4 * 1024;
    private const long MaximumLifetimeSeconds = 10;
    private static readonly byte[] WebRtcBindingDomain = Encoding.UTF8.GetBytes("HS-WEBRTC-DTLS-SCTP-V1\0");
    private static readonly byte[] WebRtcProductLabel = Encoding.UTF8.GetBytes("hs-product");

    internal sealed class Claims
    {
        public Claims() { }

        [JsonPropertyName("version")]
        public byte Version { get; init; }

        [JsonPropertyName("grant_id")]
        public required string GrantId { get; init; }

        [JsonPropertyName("deployment_id")]
        public required string DeploymentId { get; init; }

        [JsonPropertyName("account_id")]
        public required string AccountId { get; init; }

        [JsonPropertyName("manager_id")]
        public required string ManagerId { get; init; }

        [JsonPropertyName("manager_public_key")]
        public required string ManagerPublicKey { get; init; }

        [JsonPropertyName("computer_id")]
        public required string ComputerId { get; init; }

        [JsonPropertyName("endpoint_public_key")]
        public required string EndpointPublicKey { get; init; }

        [JsonPropertyName("endpoint_session_id")]
        public required string EndpointSessionId { get; init; }

        [JsonPropertyName("enrollment_epoch")]
        public long EnrollmentEpoch { get; init; }

        [JsonPropertyName("issued_at_unix")]
        public long IssuedAtUnix { get; init; }

        [JsonPropertyName("expires_at_unix")]
        public long ExpiresAtUnix { get; init; }

        [JsonPropertyName("capability")]
        public required string Capability { get; init; }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>
    /// Verify signature, canonical encoding, freshness, and exact endpoint
    /// binding before any capture or media operation.
    /// </summary>
    public static VerifiedObservationAdmissionGrant Verify(
        string token,
        string serverPublicKeyHex,
        ObservationAdmissionEndpoint expected,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(serverPublicKeyHex);
        if (Encoding.UTF8.GetByteCount(token) > MaximumTokenBytes || token.Any(static c => c > 0x7f))
        {
            throw InvalidGrant();
        }

        string[] parts = token.Split('.', StringSplitOptions.None);
        if (parts.Length != 2 || parts[0].Length == 0 || !IsLowerHex(parts[1], 64))
        {
            throw InvalidGrant();
        }

        byte[] payload = DecodeCanonicalBase64Url(parts[0]);
        byte[] signature = Convert.FromHexString(parts[1]);
        byte[] serverPublicKey = ParseLowerHex(serverPublicKeyHex, 32);
        byte[] signedMessage = new byte[Domain.Length + payload.Length];
        Domain.CopyTo(signedMessage, 0);
        payload.CopyTo(signedMessage, Domain.Length);
        try
        {
            if (payload.Length > MaximumPayloadBytes || signature.Length != 64 ||
                !Ed25519DeviceKey.VerifyHex(serverPublicKeyHex, signedMessage, signature))
            {
                throw InvalidGrant();
            }

            Claims claims;
            try
            {
                claims = JsonSerializer.Deserialize<Claims>(payload, JsonOptions)
                    ?? throw InvalidGrant();
            }
            catch (JsonException)
            {
                throw InvalidGrant();
            }

            long nowUnix = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
            if (!IsValidClaims(claims, expected, nowUnix) ||
                !CanonicalPayload(claims).AsSpan().SequenceEqual(payload))
            {
                throw InvalidGrant();
            }

            return new VerifiedObservationAdmissionGrant(claims);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(serverPublicKey);
            CryptographicOperations.ZeroMemory(signedMessage);
        }
    }

    /// <summary>Create a fresh random 32-byte lowercase-hex endpoint nonce.</summary>
    public static string CreateEndpointNonce() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    /// <summary>
    /// Validate the exact canonical tuple exported by the native verified
    /// WebRTC channel and return its lowercase hex form.
    /// </summary>
    public static string? CanonicalChannelBindingHex(byte[] binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        var expectedLength = WebRtcBindingDomain.Length + 2 + WebRtcProductLabel.Length + 2 + 64;
        if (binding.Length != expectedLength ||
            !binding.AsSpan(0, WebRtcBindingDomain.Length).SequenceEqual(WebRtcBindingDomain))
        {
            return null;
        }
        var cursor = WebRtcBindingDomain.Length;
        var labelLength = (binding[cursor] << 8) | binding[cursor + 1];
        cursor += 2;
        if (labelLength != WebRtcProductLabel.Length ||
            !binding.AsSpan(cursor, WebRtcProductLabel.Length).SequenceEqual(WebRtcProductLabel))
        {
            return null;
        }
        cursor += WebRtcProductLabel.Length;
        var streamId = (binding[cursor] << 8) | binding[cursor + 1];
        if (streamId == ushort.MaxValue)
        {
            return null;
        }
        cursor += 2;
        var first = binding.AsSpan(cursor, 32);
        var second = binding.AsSpan(cursor + 32, 32);
        if (first.SequenceCompareTo(second) > 0)
        {
            return null;
        }
        return Convert.ToHexString(binding).ToLowerInvariant();
    }

    public static bool IsCanonicalChannelBindingHex(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!IsLowerHex(value, WebRtcBindingDomain.Length + 2 + WebRtcProductLabel.Length + 2 + 64))
        {
            return false;
        }
        try
        {
            var bytes = Convert.FromHexString(value);
            return string.Equals(CanonicalChannelBindingHex(bytes), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static bool IsLowerHex(string value, int byteCount) =>
        value.Length == byteCount * 2 && value.All(static c =>
            c is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static bool IsCertificatePem(ReadOnlySpan<byte> certificatePem)
    {
        ReadOnlySpan<byte> begin = "-----BEGIN CERTIFICATE-----\n"u8;
        ReadOnlySpan<byte> end = "-----END CERTIFICATE-----\n"u8;
        if (certificatePem.Length is 0 or > 4096 ||
            !certificatePem.StartsWith(begin) || !certificatePem.EndsWith(end) ||
            certificatePem.Contains((byte)0))
        {
            return false;
        }

        foreach (byte value in certificatePem)
        {
            if (value > 0x7f) return false;
        }

        ReadOnlySpan<byte> body = certificatePem[begin.Length..^end.Length];
        if (body.IsEmpty) return false;
        foreach (byte value in body)
        {
            if (!(value is >= (byte)'A' and <= (byte)'Z' or
                  >= (byte)'a' and <= (byte)'z' or
                  >= (byte)'0' and <= (byte)'9' or
                  (byte)'+' or (byte)'/' or (byte)'=' or (byte)'\n'))
            {
                return false;
            }
        }
        return true;
    }

    internal static ServerClientException InvalidGrant() => new(
        ServerClientFailure.Unauthorized,
        "The endpoint observation grant is invalid or expired.");

    private static bool IsValidClaims(
        Claims claims,
        ObservationAdmissionEndpoint expected,
        long nowUnix) =>
        claims.Version == 1 &&
        claims.Capability == "observe" &&
        IsCanonicalUuid(claims.GrantId) &&
        IsCanonicalUuid(claims.AccountId) &&
        IsCanonicalUuid(claims.ManagerId) &&
        IsCanonicalUuid(claims.ComputerId) &&
        IsCanonicalUuid(claims.EndpointSessionId) &&
        IsCanonicalDeploymentId(claims.DeploymentId) &&
        IsLowerHex(claims.ManagerPublicKey, 32) &&
        IsLowerHex(claims.EndpointPublicKey, 32) &&
        claims.EnrollmentEpoch > 0 &&
        claims.IssuedAtUnix <= nowUnix + 5 &&
        claims.ExpiresAtUnix > nowUnix &&
        claims.ExpiresAtUnix > claims.IssuedAtUnix &&
        claims.IssuedAtUnix >= claims.ExpiresAtUnix - MaximumLifetimeSeconds &&
        claims.DeploymentId == expected.DeploymentId &&
        claims.ComputerId == expected.ComputerId &&
        claims.EndpointPublicKey == expected.EndpointPublicKeyHex &&
        claims.EndpointSessionId == expected.EndpointSessionId &&
        claims.EnrollmentEpoch == expected.EnrollmentEpoch;

    private static bool IsCanonicalUuid(string value) =>
        Guid.TryParseExact(value, "D", out Guid parsed) &&
        parsed.ToString("D").Equals(value, StringComparison.Ordinal);

    private static bool IsCanonicalDeploymentId(string value) =>
        value.Length == 36 && value.StartsWith("dep_", StringComparison.Ordinal) &&
        IsLowerHex(value[4..], 16);

    private static byte[] CanonicalPayload(Claims claims)
    {
        string json = FormattableString.Invariant(
            $"{{\"version\":{claims.Version},\"grant_id\":\"{claims.GrantId}\",\"deployment_id\":\"{claims.DeploymentId}\",\"account_id\":\"{claims.AccountId}\",\"manager_id\":\"{claims.ManagerId}\",\"manager_public_key\":\"{claims.ManagerPublicKey}\",\"computer_id\":\"{claims.ComputerId}\",\"endpoint_public_key\":\"{claims.EndpointPublicKey}\",\"endpoint_session_id\":\"{claims.EndpointSessionId}\",\"enrollment_epoch\":{claims.EnrollmentEpoch},\"issued_at_unix\":{claims.IssuedAtUnix},\"expires_at_unix\":{claims.ExpiresAtUnix},\"capability\":\"{claims.Capability}\"}}");
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] DecodeCanonicalBase64Url(string value)
    {
        if (value.Any(static c =>
                !(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
        {
            throw InvalidGrant();
        }

        string standard = value.Replace('-', '+').Replace('_', '/');
        standard += new string('=', (4 - standard.Length % 4) % 4);
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(standard);
        }
        catch (FormatException)
        {
            throw InvalidGrant();
        }

        string canonical = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (!canonical.Equals(value, StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw InvalidGrant();
        }
        return bytes;
    }

    private static byte[] ParseLowerHex(string value, int byteCount)
    {
        if (!IsLowerHex(value, byteCount))
        {
            throw InvalidGrant();
        }
        return Convert.FromHexString(value);
    }
}
