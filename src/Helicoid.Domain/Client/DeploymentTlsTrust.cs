using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Helicoid.Domain.Client;

/// <summary>
/// Named failures for deployment TLS trust inputs and request-target checks.
/// Messages never include certificate private material, fingerprints of
/// unrelated certificates, or credentials.
/// </summary>
public sealed class DeploymentTlsTrustException : Exception
{
    public DeploymentTlsTrustException(DeploymentTlsTrustFailure failure, string message, Exception? inner = null)
        : base(message, inner)
    {
        Failure = failure;
    }

    public DeploymentTlsTrustFailure Failure { get; }
}

public enum DeploymentTlsTrustFailure
{
    InvalidDeploymentId = 0,
    InvalidOrigin = 1,
    InvalidCaCertificate = 2,
    InvalidFingerprint = 3,
    FingerprintMismatch = 4,
    OriginMismatch = 5,
    InvalidRequestTarget = 6,
}

/// <summary>
/// Immutable deployment TLS trust inputs. Trust is supplied by an operator or
/// verified bootstrap channel and is never learned from the HTTPS peer.
/// Transport trust only — this is not account authentication or enrollment.
/// CA DER bytes are owned privately; mutation of caller arrays or any exposed
/// copy cannot change the anchor the pin was bound to.
/// </summary>
public sealed class DeploymentTlsTrust
{
    /// <summary>Maximum accepted deployment identity length.</summary>
    public const int MaxDeploymentIdLength = 128;

    /// <summary>Maximum accepted CA DER size (64 KiB).</summary>
    public const int MaxCaDerBytes = 64 * 1024;

    /// <summary>SHA-256 hex fingerprint length (64 characters).</summary>
    public const int Sha256HexLength = 64;

    private readonly byte[] _caDer;

    private DeploymentTlsTrust(
        string deploymentId,
        Uri origin,
        byte[] caDer,
        string caFingerprintSha256Hex)
    {
        DeploymentId = deploymentId;
        Origin = origin;
        _caDer = caDer;
        CaFingerprintSha256Hex = caFingerprintSha256Hex;
    }

    public string DeploymentId { get; }

    /// <summary>Canonical HTTPS origin (scheme, host, port). Root path only.</summary>
    public Uri Origin { get; }

    /// <summary>Lowercase hex SHA-256 of the owned CA DER bytes.</summary>
    public string CaFingerprintSha256Hex { get; }

    /// <summary>DER size of the pinned CA certificate.</summary>
    public int CaDerLength => _caDer.Length;

    /// <summary>
    /// Returns a defensive copy of the owned CA DER. Mutating the copy cannot
    /// alter the pinned anchor.
    /// </summary>
    public byte[] CopyCaDer() => _caDer.ToArray();

    /// <summary>
    /// Validates operator-supplied trust inputs before any network request.
    /// The fingerprint must match the SHA-256 of exactly the supplied CA DER.
    /// The CA must be a certificate authority (BasicConstraints CA=true, and
    /// KeyCertSign when KeyUsage is present). The DER is copied privately so
    /// later mutation of the caller buffer cannot retarget trust.
    /// </summary>
    public static DeploymentTlsTrust Create(
        string? deploymentId,
        Uri? origin,
        byte[]? caDer,
        string? caFingerprintSha256Hex)
    {
        var id = ValidateDeploymentId(deploymentId);
        var canonicalOrigin = ValidateOrigin(origin);
        var der = ValidateCaDer(caDer);
        var expectedFingerprint = ValidateFingerprintFormat(caFingerprintSha256Hex);
        var actualFingerprint = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
        if (!string.Equals(expectedFingerprint, actualFingerprint, StringComparison.Ordinal))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.FingerprintMismatch,
                "CA fingerprint does not match the supplied certificate DER.");
        }

        return new DeploymentTlsTrust(id, canonicalOrigin, der, actualFingerprint);
    }

    /// <summary>
    /// Builds a same-origin request target from a root-relative path or a
    /// same-origin absolute URI. Raw target text is validated before any URI
    /// normalization: fragments, backslashes, illegal controls, encoded
    /// slash/backslash, and semantic path-segment traversal are refused.
    /// Ordinary dot-containing filenames and query values are allowed.
    /// </summary>
    public Uri ResolveRequestTarget(string? requestTarget)
    {
        if (string.IsNullOrWhiteSpace(requestTarget))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target is required.");
        }

        var target = requestTarget.Trim();

        // Inspect raw text before any Uri constructor canonicalization.
        ValidateRawTargetText(target);

        // Root-relative targets are the normal path. Unix Uri parsing treats
        // "/x" as a file absolute URI, so classify by leading '/' first.
        if (target.StartsWith("/", StringComparison.Ordinal))
        {
            return ResolveRootRelative(target);
        }

        return ResolveAbsoluteSameOrigin(target);
    }

    public bool IsSameOrigin(Uri candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        return candidate.IsAbsoluteUri
            && string.Equals(candidate.Scheme, Origin.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(candidate.Host, Origin.Host, StringComparison.OrdinalIgnoreCase)
            && candidate.Port == Origin.Port;
    }

    /// <summary>
    /// Creates an independent certificate handle for chain trust stores.
    /// Loaded from the owned bytes only; the pin is revalidated against those
    /// bytes so the returned handle is exactly the bound anchor.
    /// </summary>
    public X509Certificate2 CreateCaCertificate()
    {
        var actualFingerprint = Convert.ToHexString(SHA256.HashData(_caDer)).ToLowerInvariant();
        if (!string.Equals(actualFingerprint, CaFingerprintSha256Hex, StringComparison.Ordinal))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.FingerprintMismatch,
                "CA fingerprint no longer matches the owned certificate DER.");
        }

        try
        {
            return X509CertificateLoader.LoadCertificate(_caDer);
        }
        catch (CryptographicException ex)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidCaCertificate,
                "CA certificate could not be loaded.",
                ex);
        }
    }

    private static void ValidateRawTargetText(string target)
    {
        foreach (var ch in target)
        {
            if (ch <= 0x1F || ch == 0x7F)
            {
                throw new DeploymentTlsTrustException(
                    DeploymentTlsTrustFailure.InvalidRequestTarget,
                    "Request target contains illegal control characters.");
            }
        }

        // Fragment is never sent to the server and must not appear in a request
        // target. Backslash is a traversal/scheme-escape vehicle on some stacks.
        if (target.Contains('#', StringComparison.Ordinal)
            || target.Contains('\\', StringComparison.Ordinal))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target must not include a fragment or backslash.");
        }

        if (target.Contains('\0'))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target contains illegal characters.");
        }
    }

    private Uri ResolveRootRelative(string target)
    {
        if (target.StartsWith("//", StringComparison.Ordinal))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Protocol-relative request targets are refused.");
        }

        // Split off query before path-segment checks so innocent query values
        // (including those containing "..") are not treated as traversal.
        var queryIndex = target.IndexOf('?', StringComparison.Ordinal);
        var pathPart = queryIndex < 0 ? target : target[..queryIndex];

        if (pathPart.Contains("://", StringComparison.Ordinal))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target must not embed a scheme.");
        }

        ValidatePathSegments(pathPart);

        if (!Uri.TryCreate(Origin, target, out var resolved))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target is not a valid URI.");
        }

        if (!string.IsNullOrEmpty(resolved.Fragment))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target must not include a fragment.");
        }

        if (!IsSameOrigin(resolved))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.OriginMismatch,
                "Request target must address the configured deployment origin.");
        }

        return resolved;
    }

    private Uri ResolveAbsoluteSameOrigin(string target)
    {
        // Check the raw path before Uri canonicalizes dot segments away.
        var schemeEnd = target.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd <= 0)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target must be root-relative or a same-origin absolute URI.");
        }

        var authorityStart = schemeEnd + 3;
        var pathStart = target.IndexOf('/', authorityStart);
        if (pathStart < 0)
        {
            // https://host:port with no path — acceptable origin form.
            pathStart = target.Length;
        }

        var queryIndex = target.IndexOf('?', pathStart);
        var pathPart = queryIndex < 0 ? target[pathStart..] : target[pathStart..queryIndex];
        ValidatePathSegments(pathPart);

        if (!Uri.TryCreate(target, UriKind.Absolute, out var absolute)
            || string.Equals(absolute.Scheme, Uri.UriSchemeFile, StringComparison.OrdinalIgnoreCase))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target must be root-relative or a same-origin absolute URI.");
        }

        if (!IsSameOrigin(absolute))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.OriginMismatch,
                "Request target must address the configured deployment origin.");
        }

        if (!string.IsNullOrEmpty(absolute.UserInfo) || !string.IsNullOrEmpty(absolute.Fragment))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidRequestTarget,
                "Request target must not embed credentials or a fragment.");
        }

        // Belt-and-suspenders after canonicalization: resolved path segments
        // must still be free of traversal.
        ValidatePathSegments(absolute.AbsolutePath);
        return absolute;
    }

    /// <summary>
    /// Semantic path-segment validation on the raw (pre-URI) path. Each segment
    /// is percent-decoded once; "." / ".." / embedded separators are refused.
    /// Filenames that merely contain dots (file.txt) are allowed.
    /// </summary>
    private static void ValidatePathSegments(string path)
    {
        if (path.Length == 0)
        {
            return;
        }

        // Skip a single leading '/'; empty path is fine.
        var segments = path.Split('/');
        foreach (var segment in segments)
        {
            if (segment.Length == 0)
            {
                continue;
            }

            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(segment);
            }
            catch (UriFormatException ex)
            {
                throw new DeploymentTlsTrustException(
                    DeploymentTlsTrustFailure.InvalidRequestTarget,
                    "Request target contains invalid percent-encoding.",
                    ex);
            }

            if (decoded is "." or "..")
            {
                throw new DeploymentTlsTrustException(
                    DeploymentTlsTrustFailure.InvalidRequestTarget,
                    "Request target must not traverse paths.");
            }

            if (decoded.Contains('/', StringComparison.Ordinal)
                || decoded.Contains('\\', StringComparison.Ordinal))
            {
                throw new DeploymentTlsTrustException(
                    DeploymentTlsTrustFailure.InvalidRequestTarget,
                    "Request target must not encode path separators.");
            }

            if (decoded.Contains('\0') || decoded.Contains('#', StringComparison.Ordinal))
            {
                throw new DeploymentTlsTrustException(
                    DeploymentTlsTrustFailure.InvalidRequestTarget,
                    "Request target contains illegal characters.");
            }
        }
    }

    private static string ValidateDeploymentId(string? deploymentId)
    {
        if (string.IsNullOrWhiteSpace(deploymentId))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidDeploymentId,
                "Deployment id is required.");
        }

        var trimmed = deploymentId.Trim();
        if (trimmed.Length > MaxDeploymentIdLength)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidDeploymentId,
                "Deployment id exceeds the length limit.");
        }

        foreach (var ch in trimmed)
        {
            if (char.IsControl(ch))
            {
                throw new DeploymentTlsTrustException(
                    DeploymentTlsTrustFailure.InvalidDeploymentId,
                    "Deployment id contains illegal characters.");
            }
        }

        return trimmed;
    }

    private static Uri ValidateOrigin(Uri? origin)
    {
        ArgumentNullException.ThrowIfNull(origin);

        if (!origin.IsAbsoluteUri)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidOrigin,
                "Deployment origin must be an absolute URI.");
        }

        if (!string.Equals(origin.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidOrigin,
                "Deployment origin must use HTTPS.");
        }

        if (string.IsNullOrEmpty(origin.Host))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidOrigin,
                "Deployment origin must include a host.");
        }

        if (!string.IsNullOrEmpty(origin.UserInfo))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidOrigin,
                "Deployment origin must not embed credentials.");
        }

        if (!string.IsNullOrEmpty(origin.Fragment))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidOrigin,
                "Deployment origin must not include a fragment.");
        }

        if (!string.IsNullOrEmpty(origin.Query))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidOrigin,
                "Deployment origin must not include a query.");
        }

        if (!string.IsNullOrEmpty(origin.AbsolutePath) && origin.AbsolutePath != "/")
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidOrigin,
                "Deployment origin must not include a path.");
        }

        var builder = new UriBuilder(origin)
        {
            Scheme = Uri.UriSchemeHttps,
            Path = "/",
            Query = string.Empty,
            Fragment = string.Empty,
            UserName = string.Empty,
            Password = string.Empty,
        };
        return builder.Uri;
    }

    private static byte[] ValidateCaDer(byte[]? caDer)
    {
        if (caDer is null || caDer.Length == 0)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidCaCertificate,
                "CA certificate DER is required.");
        }

        if (caDer.Length > MaxCaDerBytes)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidCaCertificate,
                "CA certificate DER exceeds the size limit.");
        }

        // Own a private copy so caller mutation after Create cannot retarget trust.
        var owned = caDer.ToArray();

        X509Certificate2 probe;
        try
        {
            probe = X509CertificateLoader.LoadCertificate(owned);
        }
        catch (CryptographicException ex)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidCaCertificate,
                "CA certificate DER is not a valid X.509 certificate.",
                ex);
        }

        using (probe)
        {
            ValidateCaConstraints(probe);
            _ = probe.RawData;
        }

        return owned;
    }

    /// <summary>
    /// The pinned anchor must be a certificate authority. Leaf-as-anchor is
    /// refused. When KeyUsage is present it must include KeyCertSign.
    /// </summary>
    private static void ValidateCaConstraints(X509Certificate2 certificate)
    {
        X509BasicConstraintsExtension? basic = null;
        X509KeyUsageExtension? keyUsage = null;
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509BasicConstraintsExtension bc)
            {
                basic = bc;
            }
            else if (extension is X509KeyUsageExtension ku)
            {
                keyUsage = ku;
            }
        }

        if (basic is null || !basic.CertificateAuthority)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidCaCertificate,
                "CA certificate must be a certificate authority (BasicConstraints CA=true).");
        }

        if (keyUsage is not null
            && (keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidCaCertificate,
                "CA certificate must include KeyCertSign when KeyUsage is present.");
        }
    }

    private static string ValidateFingerprintFormat(string? fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidFingerprint,
                "CA fingerprint is required.");
        }

        var trimmed = fingerprint.Trim();
        if (trimmed.Length != Sha256HexLength)
        {
            throw new DeploymentTlsTrustException(
                DeploymentTlsTrustFailure.InvalidFingerprint,
                "CA fingerprint must be a SHA-256 hex digest.");
        }

        foreach (var ch in trimmed)
        {
            var hex = ch is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');
            if (!hex)
            {
                throw new DeploymentTlsTrustException(
                    DeploymentTlsTrustFailure.InvalidFingerprint,
                    "CA fingerprint must be a SHA-256 hex digest.");
            }
        }

        return trimmed.ToLowerInvariant();
    }
}
