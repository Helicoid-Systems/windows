using System.Security.Cryptography;
using System.Text;

namespace Helicoid.Domain.Client;

/// <summary>Strict parser for the Manager's signed, session-level SDP identity attribute.</summary>
public static class ObservationPeerOffer
{
    private const string AttributePrefix = "a=hs-observation-cert-v1:";
    private const int MaximumSdpBytes = 64 * 1024;

    /// <summary>
    /// Verify the Manager certificate against this admission grant and nonce,
    /// remove the product attribute, and return the SDP for native parsing.
    /// </summary>
    public static string RemoveAndVerifyManagerCertificateAttestation(
        string offerSdp,
        VerifiedObservationAdmissionGrant grant,
        string endpointNonceHex,
        out byte[] managerCertificatePem)
    {
        ArgumentNullException.ThrowIfNull(offerSdp);
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(endpointNonceHex);
        managerCertificatePem = Array.Empty<byte>();

        if (Encoding.UTF8.GetByteCount(offerSdp) is 0 or > MaximumSdpBytes ||
            offerSdp.Any(static character => character > 0x7f || character == '\0') ||
            !offerSdp.StartsWith("v=0\r\n", StringComparison.Ordinal) ||
            HasInvalidLineEndings(offerSdp))
        {
            throw InvalidOffer();
        }

        string[] lines = offerSdp.Split("\r\n", StringSplitOptions.None);
        int firstMediaLine = Array.FindIndex(lines, static line => line.StartsWith("m=", StringComparison.Ordinal));
        if (firstMediaLine < 0)
        {
            throw InvalidOffer();
        }

        int attributeLine = -1;
        for (int index = 0; index < lines.Length; index++)
        {
            if (!lines[index].StartsWith(AttributePrefix, StringComparison.Ordinal))
            {
                continue;
            }
            if (attributeLine >= 0 || index >= firstMediaLine)
            {
                throw InvalidOffer();
            }
            attributeLine = index;
        }
        if (attributeLine < 0)
        {
            throw InvalidOffer();
        }

        string attestation = lines[attributeLine][AttributePrefix.Length..];
        int separator = attestation.IndexOf('.');
        if (separator <= 0 || separator != attestation.LastIndexOf('.') ||
            !IsLowerHex(attestation[(separator + 1)..], 64))
        {
            throw InvalidOffer();
        }

        byte[] certificatePem = DecodeCanonicalBase64Url(attestation[..separator]);
        try
        {
            if (!ObservationAdmissionGrantVerifier.IsCertificatePem(certificatePem) ||
                !grant.VerifyPeerCertificateAttestation(
                    certificatePem,
                    endpointNonceHex,
                    ObservationPeerRole.Manager,
                    attestation[(separator + 1)..]))
            {
                throw InvalidOffer();
            }

            string[] cleanLines = new string[lines.Length - 1];
            Array.Copy(lines, 0, cleanLines, 0, attributeLine);
            Array.Copy(lines, attributeLine + 1, cleanLines, attributeLine, lines.Length - attributeLine - 1);
            string cleanSdp = string.Join("\r\n", cleanLines);
            if (Encoding.UTF8.GetByteCount(cleanSdp) is 0 or > MaximumSdpBytes)
            {
                throw InvalidOffer();
            }

            managerCertificatePem = certificatePem;
            certificatePem = Array.Empty<byte>();
            return cleanSdp;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(certificatePem);
        }
    }

    private static byte[] DecodeCanonicalBase64Url(string encoded)
    {
        if (encoded.Length == 0 || encoded.Contains('=') ||
            encoded.Any(static character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')) ||
            encoded.Length % 4 == 1)
        {
            throw InvalidOffer();
        }

        string standard = encoded.Replace('-', '+').Replace('_', '/');
        standard = standard.PadRight(standard.Length + ((4 - standard.Length % 4) % 4), '=');
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(standard);
        }
        catch (FormatException)
        {
            throw InvalidOffer();
        }

        string canonical = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (!string.Equals(canonical, encoded, StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw InvalidOffer();
        }
        return decoded;
    }

    private static bool HasInvalidLineEndings(string value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            if (value[index] == '\n' && (index == 0 || value[index - 1] != '\r'))
            {
                return true;
            }
            if (value[index] == '\r' && (index + 1 >= value.Length || value[index + 1] != '\n'))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsLowerHex(string value, int byteCount) =>
        value.Length == byteCount * 2 && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static ServerClientException InvalidOffer() => new(
        ServerClientFailure.InvalidResponse,
        "The Manager observation offer is invalid or its certificate identity is unverified.");
}
