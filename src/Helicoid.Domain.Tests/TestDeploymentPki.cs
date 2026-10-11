using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Helicoid.Domain.Tests;

/// <summary>
/// TEST-ONLY disposable PKI for real TLS socket proofs. Generated at runtime
/// via CertificateRequest; nothing here enters normal application operation.
/// </summary>
internal sealed class TestDeploymentPki : IDisposable
{
    private TestDeploymentPki(X509Certificate2 ca)
    {
        Ca = ca;
        CaDer = ca.RawData;
        CaFingerprintSha256Hex = Convert.ToHexString(SHA256.HashData(CaDer)).ToLowerInvariant();
    }

    public X509Certificate2 Ca { get; }

    public byte[] CaDer { get; }

    public string CaFingerprintSha256Hex { get; }

    public static TestDeploymentPki Create(string commonName = "HS Test Deployment CA")
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true,
            hasPathLengthConstraint: true,
            pathLengthConstraint: 0,
            critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(
            request.PublicKey,
            critical: false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-60);
        var notAfter = DateTimeOffset.UtcNow.AddYears(1);
        var ca = request.CreateSelfSigned(notBefore, notAfter);
        // Keep an independent private-key handle for leaf issuance.
        return new TestDeploymentPki(ca);
    }

    public X509Certificate2 CreateLeaf(
        string? dnsName = "localhost",
        IPAddress? ipAddress = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool includeServerAuthEku = true,
        bool includeClientAuthEku = false,
        string commonName = "HS Test Leaf")
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(
            request.PublicKey,
            critical: false));

        var san = new SubjectAlternativeNameBuilder();
        var hasSan = false;
        if (!string.IsNullOrWhiteSpace(dnsName))
        {
            san.AddDnsName(dnsName);
            hasSan = true;
        }

        if (ipAddress is not null)
        {
            san.AddIpAddress(ipAddress);
            hasSan = true;
        }

        if (hasSan)
        {
            request.CertificateExtensions.Add(san.Build());
        }

        var eku = new OidCollection();
        if (includeServerAuthEku)
        {
            eku.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        }

        if (includeClientAuthEku)
        {
            eku.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        }

        if (eku.Count > 0)
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, critical: true));
        }

        var start = notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5);
        var end = notAfter ?? DateTimeOffset.UtcNow.AddHours(2);
        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        if (serial.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            serial[15] = 1;
        }

        var signed = request.Create(Ca, start, end, serial);
        try
        {
            return signed.CopyWithPrivateKey(key);
        }
        catch
        {
            signed.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Ca.Dispose();
    }
}

/// <summary>TEST-ONLY scripted HTTPS response bytes.</summary>
internal static class TestHttpScripts
{
    public static byte[] Json(string json, int status = 200) =>
        Raw(status, "application/json", System.Text.Encoding.UTF8.GetBytes(json));

    public static byte[] Text(string body, int status = 200) =>
        Raw(status, "text/plain", System.Text.Encoding.UTF8.GetBytes(body));

    public static byte[] Raw(int status, string contentType, byte[] body)
    {
        var head =
            $"HTTP/1.1 {status} {(status == 200 ? "OK" : "Scripted")}\r\n" +
            $"Content-Type: {contentType}\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: close\r\n" +
            "\r\n";
        var headBytes = System.Text.Encoding.ASCII.GetBytes(head);
        var payload = new byte[headBytes.Length + body.Length];
        headBytes.CopyTo(payload, 0);
        body.CopyTo(payload, headBytes.Length);
        return payload;
    }

    public static byte[] Redirect(string location, int status = 302)
    {
        var body = Array.Empty<byte>();
        var head =
            $"HTTP/1.1 {status} Redirect\r\n" +
            $"Location: {location}\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n" +
            "\r\n";
        return System.Text.Encoding.ASCII.GetBytes(head);
    }

    public static byte[] AuthChallenge(int status = 401)
    {
        var head =
            $"HTTP/1.1 {status} Unauthorized\r\n" +
            "WWW-Authenticate: Bearer realm=\"deployment\"\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n" +
            "\r\n";
        return System.Text.Encoding.ASCII.GetBytes(head);
    }

    public static byte[] Chunked(int chunkCount, int chunkSize)
    {
        var chunks = new List<byte>();
        for (var i = 0; i < chunkCount; i++)
        {
            var chunk = new byte[chunkSize];
            new byte[] { (byte)'A' }.CopyTo(chunk, 0);
            var sizeLine = System.Text.Encoding.ASCII.GetBytes($"{chunkSize:X}\r\n");
            chunks.AddRange(sizeLine);
            chunks.AddRange(chunk);
            chunks.AddRange(System.Text.Encoding.ASCII.GetBytes("\r\n"));
        }

        chunks.AddRange(System.Text.Encoding.ASCII.GetBytes("0\r\n\r\n"));
        var body = chunks.ToArray();
        var head =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            "Transfer-Encoding: chunked\r\n" +
            "Connection: close\r\n" +
            "\r\n";
        var headBytes = System.Text.Encoding.ASCII.GetBytes(head);
        var payload = new byte[headBytes.Length + body.Length];
        headBytes.CopyTo(payload, 0);
        body.CopyTo(payload, headBytes.Length);
        return payload;
    }
}
