using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Helicoid.Domain.Client;

/// <summary>
/// An endpoint observation challenge whose identity claims and ephemeral
/// certificate attestation were checked against a verified admission grant.
/// The certificate is public data; only the copy returned by
/// <see cref="CopyEndpointCertificatePem"/> should be pinned by the native peer.
/// </summary>
public sealed class VerifiedObservationEndpointChallenge
{
    private readonly byte[] _certificatePem;

    internal VerifiedObservationEndpointChallenge(
        string computerId,
        string endpointSessionId,
        string endpointNonceHex,
        long expiresAtUnix,
        byte[] certificatePem)
    {
        ComputerId = computerId;
        EndpointSessionId = endpointSessionId;
        EndpointNonceHex = endpointNonceHex;
        ExpiresAtUnix = expiresAtUnix;
        _certificatePem = certificatePem;
    }

    public string ComputerId { get; }
    public string EndpointSessionId { get; }
    public string EndpointNonceHex { get; }
    public long ExpiresAtUnix { get; }

    public ReadOnlyMemory<byte> EndpointCertificatePem => _certificatePem;

    public byte[] CopyEndpointCertificatePem() => (byte[])_certificatePem.Clone();
}

/// <summary>
/// Strict Manager-side verifier for the endpoint's first observation signal.
/// The challenge is unsigned JSON, so every identity claim must match the
/// server-signed grant and the endpoint certificate attestation must verify
/// under the endpoint key named by that grant.
/// The deployment server still accepts the four-claim challenge without
/// <c>endpoint_certificate_pem</c>/<c>endpoint_certificate_signature</c> as a
/// compatibility form, but the Manager rejects it: without an attestation it
/// cannot pin the endpoint's DTLS identity. This mirrors the deployment
/// authority in <c>apps/manager/src/observation_admission.cpp</c> and the
/// server's <c>validate_endpoint_observation_challenge</c>.
/// </summary>
public static class ObservationEndpointChallenge
{
    private const int MaximumPayloadBytes = 4096;
    private const int MaximumCertificateBytes = 4096;

    private static readonly HashSet<string> RequiredProperties = new(StringComparer.Ordinal)
    {
        "computer_id",
        "endpoint_session_id",
        "endpoint_nonce",
        "expires_at_unix",
        "endpoint_certificate_pem",
        "endpoint_certificate_signature",
    };

    /// <summary>
    /// Verify one endpoint challenge payload against the verified grant before
    /// the Manager creates an offer or trusts any endpoint certificate.
    /// </summary>
    public static VerifiedObservationEndpointChallenge Verify(
        string payload,
        VerifiedObservationAdmissionGrant grant,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(grant);

        // ASCII-only input makes character count equal UTF-8 byte count.
        if (payload.Length is 0 or > MaximumPayloadBytes ||
            payload.Any(static character => character > 0x7f || character == '\0'))
        {
            throw InvalidChallenge();
        }

        ChallengeClaims claims = ParseClaims(payload);
        long nowUnix = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        if (!string.Equals(claims.ComputerId, grant.ComputerId, StringComparison.Ordinal) ||
            !string.Equals(claims.EndpointSessionId, grant.EndpointSessionId, StringComparison.Ordinal) ||
            !ObservationAdmissionGrantVerifier.IsLowerHex(claims.EndpointNonceHex, 32) ||
            claims.ExpiresAtUnix != grant.ExpiresAtUnix ||
            claims.ExpiresAtUnix <= nowUnix)
        {
            throw InvalidChallenge();
        }

        byte[] certificatePem = Encoding.UTF8.GetBytes(claims.EndpointCertificatePem);
        try
        {
            if (certificatePem.Length > MaximumCertificateBytes ||
                !grant.VerifyPeerCertificateAttestation(
                    certificatePem,
                    claims.EndpointNonceHex,
                    ObservationPeerRole.Endpoint,
                    claims.EndpointCertificateSignature,
                    nowUnix))
            {
                throw InvalidChallenge();
            }

            return new VerifiedObservationEndpointChallenge(
                claims.ComputerId,
                claims.EndpointSessionId,
                claims.EndpointNonceHex,
                claims.ExpiresAtUnix,
                certificatePem.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(certificatePem);
        }
    }

    private static ChallengeClaims ParseClaims(string payload)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions
            {
                MaxDepth = 1,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw InvalidChallenge();
            }

            var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (!RequiredProperties.Contains(property.Name) ||
                    !values.TryAdd(property.Name, property.Value))
                {
                    throw InvalidChallenge();
                }
            }
            if (values.Count != RequiredProperties.Count)
            {
                throw InvalidChallenge();
            }

            return new ChallengeClaims(
                ReadString(values, "computer_id"),
                ReadString(values, "endpoint_session_id"),
                ReadString(values, "endpoint_nonce"),
                ReadInteger(values, "expires_at_unix"),
                ReadString(values, "endpoint_certificate_pem"),
                ReadString(values, "endpoint_certificate_signature"));
        }
        catch (JsonException)
        {
            throw InvalidChallenge();
        }
    }

    private static string ReadString(Dictionary<string, JsonElement> values, string name)
    {
        JsonElement value = values[name];
        if (value.ValueKind != JsonValueKind.String)
        {
            throw InvalidChallenge();
        }
        return value.GetString() ?? throw InvalidChallenge();
    }

    private static long ReadInteger(Dictionary<string, JsonElement> values, string name)
    {
        JsonElement value = values[name];
        if (value.ValueKind != JsonValueKind.Number ||
            value.GetRawText().Any(static character => character is '.' or 'e' or 'E') ||
            !value.TryGetInt64(out long result))
        {
            throw InvalidChallenge();
        }
        return result;
    }

    private static ServerClientException InvalidChallenge() => new(
        ServerClientFailure.InvalidResponse,
        "The endpoint observation challenge is invalid or does not match the verified grant.");

    private sealed record ChallengeClaims(
        string ComputerId,
        string EndpointSessionId,
        string EndpointNonceHex,
        long ExpiresAtUnix,
        string EndpointCertificatePem,
        string EndpointCertificateSignature);
}
