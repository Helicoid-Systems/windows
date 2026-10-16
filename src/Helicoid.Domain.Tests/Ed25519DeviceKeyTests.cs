using System.Security.Cryptography;
using System.Text;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Real Ed25519 proofs via NSec/libsodium. Disposable test identities only.
/// </summary>
public class Ed25519DeviceKeyTests
{
    [Fact]
    public void Create_SignVerify_RoundTrips()
    {
        using var key = Ed25519DeviceKey.Create();
        var message = Encoding.UTF8.GetBytes("hs-auth-v2|deployment:dep-1|challenge:c1|operation:session|manager:x");
        var signature = key.Sign(message);

        Assert.Equal(Ed25519DeviceKey.SignatureLength, signature.Length);
        Assert.Equal(Ed25519DeviceKey.PublicKeyLength * 2, key.PublicKeyHex.Length);
        Assert.Equal(key.PublicKeyHex, key.PublicKeyHex.ToLowerInvariant());
        Assert.True(Ed25519DeviceKey.VerifyHexSignature(key.PublicKeyHex, message, Convert.ToHexString(signature)));
    }

    [Fact]
    public void ImportSeed_DerivesStablePublicKey_AndSigns()
    {
        var seed = new byte[Ed25519DeviceKey.SeedLength];
        RandomNumberGenerator.Fill(seed);

        string publicKeyHex;
        byte[] signature;
        var message = Encoding.UTF8.GetBytes("canonical");
        using (var first = Ed25519DeviceKey.ImportSeed(seed.ToArray()))
        {
            publicKeyHex = first.PublicKeyHex;
            signature = first.Sign(message);
        }

        using var second = Ed25519DeviceKey.ImportSeed(seed.ToArray());
        Assert.Equal(publicKeyHex, second.PublicKeyHex);
        Assert.True(Ed25519DeviceKey.VerifyHexSignature(publicKeyHex, message, Convert.ToHexString(signature)));

        // Different seed → different key.
        var otherSeed = new byte[Ed25519DeviceKey.SeedLength];
        RandomNumberGenerator.Fill(otherSeed);
        using var other = Ed25519DeviceKey.ImportSeed(otherSeed);
        Assert.NotEqual(publicKeyHex, other.PublicKeyHex);

        CryptographicOperations.ZeroMemory(seed);
        CryptographicOperations.ZeroMemory(otherSeed);
    }

    [Fact]
    public void Verify_WrongMessageOrKeyOrSignature_Fails()
    {
        using var key = Ed25519DeviceKey.Create();
        using var other = Ed25519DeviceKey.Create();
        var message = Encoding.UTF8.GetBytes("message-a");
        var signature = key.Sign(message);
        var sigHex = Ed25519DeviceKey.ToLowerHex(signature);

        Assert.False(Ed25519DeviceKey.VerifyHexSignature(key.PublicKeyHex, Encoding.UTF8.GetBytes("message-b"), sigHex));
        Assert.False(Ed25519DeviceKey.VerifyHexSignature(other.PublicKeyHex, message, sigHex));

        var tampered = sigHex.ToCharArray();
        tampered[0] = tampered[0] == '0' ? '1' : '0';
        Assert.False(Ed25519DeviceKey.VerifyHexSignature(key.PublicKeyHex, message, new string(tampered)));
    }

    [Fact]
    public void TryParseHexExact_RequiresExactLengthAndHex()
    {
        Assert.True(Ed25519DeviceKey.TryParseHexExact("00ff", 2, out var bytes));
        Assert.Equal(new byte[] { 0x00, 0xff }, bytes);

        Assert.False(Ed25519DeviceKey.TryParseHexExact("00", 2, out _));
        Assert.False(Ed25519DeviceKey.TryParseHexExact("00ff00", 2, out _));
        Assert.False(Ed25519DeviceKey.TryParseHexExact("00fg", 2, out _));
        Assert.False(Ed25519DeviceKey.TryParseHexExact(null, 2, out _));
        Assert.False(Ed25519DeviceKey.TryParsePublicKey("00", out _));
    }

    [Fact]
    public void ToString_DoesNotLeakKeyMaterial()
    {
        using var key = Ed25519DeviceKey.Create();
        var text = key.ToString();
        Assert.DoesNotContain(key.PublicKeyHex, text);
        Assert.Equal("Ed25519DeviceKey", text);
    }

    [Fact]
    public void ImportSeed_RejectsWrongLength()
    {
        Assert.Throws<ServerClientException>(() => Ed25519DeviceKey.ImportSeed(new byte[31]));
        Assert.Throws<ServerClientException>(() => Ed25519DeviceKey.ImportSeed(new byte[33]));
    }

    [Fact]
    public void Dispose_PreventsFurtherSigning()
    {
        var key = Ed25519DeviceKey.Create();
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.Sign(Encoding.UTF8.GetBytes("x")));
    }
}
