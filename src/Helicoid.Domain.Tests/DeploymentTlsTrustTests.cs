using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

public class DeploymentTlsTrustTests
{
    private static readonly byte[] ValidCaDer = CreateSelfSignedCaDer();

    private static byte[] CreateSelfSignedCaDer()
    {
        using var pki = TestDeploymentPki.Create("HS Trust Unit CA");
        return pki.CaDer;
    }

    private static string FingerprintOf(byte[] der) =>
        Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();

    private static DeploymentTlsTrust Create(
        string? id = "dep-1",
        Uri? origin = null,
        byte[]? caDer = null,
        string? fingerprint = null,
        bool fingerprintExplicit = false)
    {
        var der = caDer ?? ValidCaDer;
        var pin = fingerprintExplicit ? fingerprint : fingerprint ?? FingerprintOf(der);
        return DeploymentTlsTrust.Create(
            id,
            origin ?? new Uri("https://deployment.example:8443/"),
            der,
            pin);
    }

    [Fact]
    public void Create_AcceptsValidInputs_AndCanonicalizesOrigin()
    {
        var trust = Create(origin: new Uri("https://deployment.example:8443"));
        Assert.Equal("dep-1", trust.DeploymentId);
        Assert.Equal(new Uri("https://deployment.example:8443/"), trust.Origin);
        Assert.Equal(FingerprintOf(ValidCaDer), trust.CaFingerprintSha256Hex);
        Assert.Equal(ValidCaDer, trust.CopyCaDer());
    }

    [Fact]
    public void Create_Fingerprint_IsCaseInsensitiveHexMatch()
    {
        var trust = Create(fingerprint: FingerprintOf(ValidCaDer).ToUpperInvariant());
        Assert.Equal(FingerprintOf(ValidCaDer), trust.CaFingerprintSha256Hex);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_RefusesEmptyDeploymentId(string? id)
    {
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(id: id));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidDeploymentId, ex.Failure);
    }

    [Fact]
    public void Create_RefusesOverlongDeploymentId()
    {
        var id = new string('a', DeploymentTlsTrust.MaxDeploymentIdLength + 1);
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(id: id));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidDeploymentId, ex.Failure);
    }

    [Fact]
    public void Create_RefusesControlCharactersInDeploymentId()
    {
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(id: "dep\u0001-1"));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidDeploymentId, ex.Failure);
    }

    [Theory]
    [InlineData("http://deployment.example:8443/")]
    [InlineData("https://deployment.example:8443/path")]
    [InlineData("https://user:pass@deployment.example:8443/")]
    [InlineData("https://deployment.example:8443/#frag")]
    [InlineData("https://deployment.example:8443/?q=1")]
    public void Create_RefusesNonOriginOrNonHttps(string origin)
    {
        var ex = Assert.Throws<DeploymentTlsTrustException>(() =>
            Create(origin: new Uri(origin)));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidOrigin, ex.Failure);
    }

    [Fact]
    public void Create_RefusesMissingCaDer()
    {
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(caDer: Array.Empty<byte>()));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidCaCertificate, ex.Failure);
    }

    [Fact]
    public void Create_RefusesOversizedCaDer()
    {
        var der = new byte[DeploymentTlsTrust.MaxCaDerBytes + 1];
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(caDer: der));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidCaCertificate, ex.Failure);
    }

    [Fact]
    public void Create_RefusesUnparseableCaDer()
    {
        var der = new byte[] { 0x30, 0x01, 0x02 };
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(caDer: der));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidCaCertificate, ex.Failure);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("zz88d5a0c1d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8")]
    public void Create_RefusesMalformedFingerprint(string? fingerprint)
    {
        var ex = Assert.Throws<DeploymentTlsTrustException>(() =>
            Create(fingerprint: fingerprint, fingerprintExplicit: true));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidFingerprint, ex.Failure);
    }

    [Fact]
    public void Create_RefusesFingerprintMismatch_BadPin()
    {
        var wrongPin = new string('0', DeploymentTlsTrust.Sha256HexLength);
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(fingerprint: wrongPin));
        Assert.Equal(DeploymentTlsTrustFailure.FingerprintMismatch, ex.Failure);
    }

    [Fact]
    public void ResolveRequestTarget_AllowsRootRelativeAndSameOrigin()
    {
        var trust = Create();
        var relative = trust.ResolveRequestTarget("/health");
        Assert.Equal("https://deployment.example:8443/health", relative.AbsoluteUri);

        var absolute = trust.ResolveRequestTarget("https://deployment.example:8443/v1/status?x=1");
        Assert.Equal("https://deployment.example:8443/v1/status?x=1", absolute.AbsoluteUri);
    }

    [Theory]
    [InlineData("//evil.example/path")]
    [InlineData("/../etc/passwd")]
    [InlineData("/a/../../etc/passwd")]
    [InlineData("/http://evil.example/")]
    [InlineData("health")]
    [InlineData("")]
    public void ResolveRequestTarget_RefusesTraversalAndEscapes(string target)
    {
        var trust = Create();
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => trust.ResolveRequestTarget(target));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidRequestTarget, ex.Failure);
    }

    [Fact]
    public void ResolveRequestTarget_RefusesForeignOrigin()
    {
        var trust = Create();
        var ex = Assert.Throws<DeploymentTlsTrustException>(() =>
            trust.ResolveRequestTarget("https://evil.example:8443/health"));
        Assert.Equal(DeploymentTlsTrustFailure.OriginMismatch, ex.Failure);
    }

    [Fact]
    public void ResolveRequestTarget_RefusesSchemeSwitch()
    {
        var trust = Create();
        var ex = Assert.Throws<DeploymentTlsTrustException>(() =>
            trust.ResolveRequestTarget("http://deployment.example:8443/health"));
        Assert.Equal(DeploymentTlsTrustFailure.OriginMismatch, ex.Failure);
    }

    [Fact]
    public void ResolveRequestTarget_RefusesCredentialsAndFragment()
    {
        var trust = Create();
        var cred = Assert.Throws<DeploymentTlsTrustException>(() =>
            trust.ResolveRequestTarget("https://user:pass@deployment.example:8443/health"));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidRequestTarget, cred.Failure);

        var frag = Assert.Throws<DeploymentTlsTrustException>(() =>
            trust.ResolveRequestTarget("https://deployment.example:8443/health#x"));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidRequestTarget, frag.Failure);
    }

    [Fact]
    public void CreateCaCertificate_LoadsIndependentHandle()
    {
        var trust = Create();
        using var a = trust.CreateCaCertificate();
        using var b = trust.CreateCaCertificate();
        Assert.False(ReferenceEquals(a, b));
        Assert.Equal(trust.CaFingerprintSha256Hex, FingerprintOf(a.RawData));
    }

    [Fact]
    public void Create_MutatingInputArray_DoesNotRetargetTrust()
    {
        var der = ValidCaDer.ToArray();
        var pin = FingerprintOf(der);
        var trust = DeploymentTlsTrust.Create(
            "dep-1",
            new Uri("https://deployment.example:8443/"),
            der,
            pin);

        // Mutate the caller's buffer after Create.
        Array.Clear(der);

        Assert.Equal(pin, trust.CaFingerprintSha256Hex);
        Assert.Equal(ValidCaDer, trust.CopyCaDer());
        using var cert = trust.CreateCaCertificate();
        Assert.Equal(pin, FingerprintOf(cert.RawData));
    }

    [Fact]
    public void CopyCaDer_IsDefensiveCopy_MutationCannotAlterTrust()
    {
        var trust = Create();
        var copy = trust.CopyCaDer();
        Array.Clear(copy);

        Assert.Equal(ValidCaDer, trust.CopyCaDer());
        using var cert = trust.CreateCaCertificate();
        Assert.Equal(trust.CaFingerprintSha256Hex, FingerprintOf(cert.RawData));
    }

    [Fact]
    public void CreateCaCertificate_RevalidatesOwnedPin()
    {
        var trust = Create();
        using var cert = trust.CreateCaCertificate();
        // The handle must be exactly the pinned anchor.
        Assert.Equal(trust.CaFingerprintSha256Hex, FingerprintOf(cert.RawData));
        Assert.Equal(ValidCaDer, cert.RawData);
    }

    [Theory]
    [InlineData("/health#fragment")]
    [InlineData("/health#")]
    [InlineData("https://deployment.example:8443/health#frag")]
    [InlineData("/a\\b")]
    [InlineData("https://deployment.example:8443/a\\b")]
    [InlineData("/a/%2e%2e/b")]
    [InlineData("/a/%2E%2E/b")]
    [InlineData("/a/%2f/b")]
    [InlineData("/a/%2F..%2Fb")]
    [InlineData("/a/%5c..%5cb")]
    [InlineData("/a/..%2f..%2fetc")]
    [InlineData("/%2e%2e/etc/passwd")]
    public void ResolveRequestTarget_RefusesEncodedTraversalBackslashFragment(string target)
    {
        var trust = Create();
        var ex = Assert.Throws<DeploymentTlsTrustException>(() => trust.ResolveRequestTarget(target));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidRequestTarget, ex.Failure);
    }

    [Fact]
    public void ResolveRequestTarget_RefusesAbsoluteSameOriginTraversal_BeforeCanonicalization()
    {
        var trust = Create();

        // Uri would canonicalize /ok/../../secret away; raw segments must refuse.
        foreach (var target in new[]
        {
            "https://deployment.example:8443/ok/../../secret",
            "https://deployment.example:8443/a/%2e%2e/b",
            "https://deployment.example:8443/../etc/passwd",
        })
        {
            var ex = Assert.Throws<DeploymentTlsTrustException>(() => trust.ResolveRequestTarget(target));
            Assert.Equal(DeploymentTlsTrustFailure.InvalidRequestTarget, ex.Failure);
        }
    }

    [Theory]
    [InlineData("/file.txt")]
    [InlineData("/dir.with.dots/file.name")]
    [InlineData("/health?file=../x")]
    [InlineData("/health?note=..&ok=1")]
    [InlineData("/search?q=a..b")]
    [InlineData("/a/b..c/d")]
    public void ResolveRequestTarget_AllowsInnocentDotsAndQueries(string target)
    {
        var trust = Create();
        var resolved = trust.ResolveRequestTarget(target);
        Assert.True(trust.IsSameOrigin(resolved));
    }

    [Theory]
    [InlineData("/health?x=1", "/health?x=1")]
    [InlineData("/v1/status?x=1&y=2", "/v1/status?x=1&y=2")]
    public void ResolveRequestTarget_AllowsQueries(string target, string expectedPathAndQuery)
    {
        var trust = Create();
        var resolved = trust.ResolveRequestTarget(target);
        Assert.True(trust.IsSameOrigin(resolved));
        Assert.Equal(expectedPathAndQuery, resolved.PathAndQuery);
    }

    [Fact]
    public void Create_RefusesLeafAsAnchor()
    {
        using var pki = TestDeploymentPki.Create();
        using var leaf = pki.CreateLeaf(dnsName: "localhost");
        var ex = Assert.Throws<DeploymentTlsTrustException>(() =>
            Create(caDer: leaf.RawData));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidCaCertificate, ex.Failure);
    }

    [Fact]
    public void Create_RefusesCaMissingKeyCertSign_WhenKeyUsagePresent()
    {
        // Self-signed cert with CA=false basic constraints and KeyUsage without KeyCertSign.
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Not A Signing CA",
            key,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        request.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.DigitalSignature,
                critical: true));
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var ex = Assert.Throws<DeploymentTlsTrustException>(() => Create(caDer: cert.RawData));
        Assert.Equal(DeploymentTlsTrustFailure.InvalidCaCertificate, ex.Failure);
    }
}
