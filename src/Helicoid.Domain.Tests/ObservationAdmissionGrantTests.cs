using System.Security.Cryptography;
using System.Text;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

public sealed class ObservationAdmissionGrantTests
{
    [Fact]
    public void Verify_BindsGrantToEndpointSession_AndAcceptsOnlyManagerProofForFreshNonce()
    {
        using var serverKey = Ed25519DeviceKey.Create();
        using var managerKey = Ed25519DeviceKey.Create();
        using var endpointKey = Ed25519DeviceKey.Create();
        const string deploymentId = "dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const string computerId = "e475b9ca-801a-4f71-b5d5-b87daaaae731";
        const string sessionId = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1";
        const string grantId = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173";
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var token = CreateToken(
            serverKey,
            grantId,
            deploymentId,
            "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d",
            "7a01cf88-6fdb-4cc1-a72f-d155f5309355",
            managerKey.PublicKeyHex,
            computerId,
            endpointKey.PublicKeyHex,
            sessionId,
            enrollmentEpoch: 3,
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9);
        var expected = new ObservationAdmissionEndpoint(
            deploymentId,
            computerId,
            endpointKey.PublicKeyHex,
            sessionId,
            EnrollmentEpoch: 3);

        var verified = ObservationAdmissionGrantVerifier.Verify(
            token,
            serverKey.PublicKeyHex,
            expected);
        var nonce = ObservationAdmissionGrantVerifier.CreateEndpointNonce();
        var channelBinding = CreateChannelBinding();
        var channelBindingHex = Assert.IsType<string>(
            ObservationAdmissionGrantVerifier.CanonicalChannelBindingHex(channelBinding));
        var proofMessage = verified.CreateManagerProofMessage(nonce, channelBindingHex);
        var signature = managerKey.Sign(proofMessage);

        Assert.Equal(grantId, verified.GrantId);
        Assert.True(verified.VerifyManagerProof(
            nonce,
            channelBindingHex,
            Ed25519DeviceKey.ToLowerHex(signature)));
        Assert.False(verified.VerifyManagerProof(
            ObservationAdmissionGrantVerifier.CreateEndpointNonce(),
            channelBindingHex,
            Ed25519DeviceKey.ToLowerHex(signature)));

        byte[] endpointCertificate = Encoding.UTF8.GetBytes(
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n");
        byte[] endpointCertificateMessage = verified.CreatePeerCertificateAttestationMessage(
            endpointCertificate,
            nonce,
            ObservationPeerRole.Endpoint);
        byte[] endpointCertificateSignature = endpointKey.Sign(endpointCertificateMessage);
        Assert.True(verified.VerifyPeerCertificateAttestation(
            endpointCertificate,
            nonce,
            ObservationPeerRole.Endpoint,
            Ed25519DeviceKey.ToLowerHex(endpointCertificateSignature)));
        Assert.False(verified.VerifyPeerCertificateAttestation(
            endpointCertificate,
            ObservationAdmissionGrantVerifier.CreateEndpointNonce(),
            ObservationPeerRole.Endpoint,
            Ed25519DeviceKey.ToLowerHex(endpointCertificateSignature)));
        Assert.False(verified.VerifyPeerCertificateAttestation(
            endpointCertificate,
            nonce,
            ObservationPeerRole.Manager,
            Ed25519DeviceKey.ToLowerHex(endpointCertificateSignature)));

        byte[] managerCertificate = Encoding.UTF8.GetBytes(
            "-----BEGIN CERTIFICATE-----\nBQYHCA==\n-----END CERTIFICATE-----\n");
        byte[] managerCertificateMessage = verified.CreatePeerCertificateAttestationMessage(
            managerCertificate,
            nonce,
            ObservationPeerRole.Manager);
        byte[] managerCertificateSignature = managerKey.Sign(managerCertificateMessage);
        Assert.True(verified.VerifyPeerCertificateAttestation(
            managerCertificate,
            nonce,
            ObservationPeerRole.Manager,
            Ed25519DeviceKey.ToLowerHex(managerCertificateSignature)));
        Assert.False(verified.VerifyPeerCertificateAttestation(
            Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"),
            nonce,
            ObservationPeerRole.Manager,
            Ed25519DeviceKey.ToLowerHex(managerCertificateSignature)));

        CryptographicOperations.ZeroMemory(endpointCertificateMessage);
        CryptographicOperations.ZeroMemory(endpointCertificateSignature);
        CryptographicOperations.ZeroMemory(managerCertificateMessage);
        CryptographicOperations.ZeroMemory(managerCertificateSignature);
        Assert.Throws<ServerClientException>(() => ObservationAdmissionGrantVerifier.Verify(
            token,
            serverKey.PublicKeyHex,
            expected with { EndpointSessionId = "c14aed02-2397-4d25-9029-2e2c4e39b338" }));
    }

    private static byte[] CreateChannelBinding()
    {
        using var bytes = new MemoryStream();
        bytes.Write(Encoding.UTF8.GetBytes("HS-WEBRTC-DTLS-SCTP-V1\0"));
        bytes.WriteByte(0);
        bytes.WriteByte(10);
        bytes.Write(Encoding.UTF8.GetBytes("hs-product"));
        bytes.WriteByte(0);
        bytes.WriteByte(7);
        bytes.Write(Enumerable.Repeat((byte)0x11, 32).ToArray());
        bytes.Write(Enumerable.Repeat((byte)0x22, 32).ToArray());
        return bytes.ToArray();
    }

    private static string CreateToken(
        Ed25519DeviceKey serverKey,
        string grantId,
        string deploymentId,
        string accountId,
        string managerId,
        string managerPublicKey,
        string computerId,
        string endpointPublicKey,
        string endpointSessionId,
        long enrollmentEpoch,
        long issuedAtUnix,
        long expiresAtUnix)
    {
        var payload = Encoding.UTF8.GetBytes(FormattableString.Invariant(
            $"{{\"version\":1,\"grant_id\":\"{grantId}\",\"deployment_id\":\"{deploymentId}\",\"account_id\":\"{accountId}\",\"manager_id\":\"{managerId}\",\"manager_public_key\":\"{managerPublicKey}\",\"computer_id\":\"{computerId}\",\"endpoint_public_key\":\"{endpointPublicKey}\",\"endpoint_session_id\":\"{endpointSessionId}\",\"enrollment_epoch\":{enrollmentEpoch},\"issued_at_unix\":{issuedAtUnix},\"expires_at_unix\":{expiresAtUnix},\"capability\":\"observe\"}}"));
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
}
