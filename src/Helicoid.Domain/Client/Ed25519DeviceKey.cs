using System.Security.Cryptography;
using NSec.Cryptography;

namespace Helicoid.Domain.Client;

/// <summary>
/// Persistent Ed25519 manager device key used for native v2 challenge proofs.
/// Backed by NSec.Cryptography (libsodium). Private seed stays in process
/// memory only while the instance is alive and is zeroed on dispose. The
/// public key is the only value that may leave the process (hex32).
/// </summary>
public sealed class Ed25519DeviceKey : IDisposable
{
    /// <summary>Raw Ed25519 seed / private key length.</summary>
    public const int SeedLength = 32;

    /// <summary>Raw Ed25519 public key length.</summary>
    public const int PublicKeyLength = 32;

    /// <summary>Ed25519 signature length.</summary>
    public const int SignatureLength = 64;

    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;

    private readonly object _gate = new();
    private Key? _key;
    private bool _disposed;

    private Ed25519DeviceKey(Key key, string publicKeyHex)
    {
        _key = key;
        PublicKeyHex = publicKeyHex;
    }

    /// <summary>Lowercase hex of the 32-byte public key.</summary>
    public string PublicKeyHex { get; }

    /// <summary>Generate a fresh disposable device key (tests / first creation).</summary>
    public static Ed25519DeviceKey Create()
    {
        // Private key is non-exportable; public key export is separate.
        var key = Key.Create(Algorithm, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.None,
        });
        return new Ed25519DeviceKey(key, ExportPublicKeyHex(key));
    }

    /// <summary>
    /// Import a 32-byte seed. The seed buffer is not retained; the key owns a
    /// private copy that is zeroed on dispose.
    /// </summary>
    public static Ed25519DeviceKey ImportSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != SeedLength)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Device key seed must be exactly 32 bytes.");
        }

        try
        {
            var key = Key.Import(
                Algorithm,
                seed,
                KeyBlobFormat.RawPrivateKey,
                new KeyCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.None,
                });
            return new Ed25519DeviceKey(key, ExportPublicKeyHex(key));
        }
        catch (CryptographicException ex)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Device key seed is not a valid Ed25519 key.",
                ex);
        }
    }

    /// <summary>Sign a message with Ed25519. Returns a 64-byte signature.</summary>
    public byte[] Sign(ReadOnlySpan<byte> message)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return Algorithm.Sign(_key!, message);
        }
    }

    /// <summary>
    /// Verify a signature against a hex public key. Unknown or malformed keys
    /// fail closed (false).
    /// </summary>
    public static bool VerifyHex(
        string publicKeyHex,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signatureBytes)
    {
        if (!TryParsePublicKey(publicKeyHex, out var publicKeyBytes))
        {
            return false;
        }

        if (signatureBytes.Length != SignatureLength)
        {
            CryptographicOperations.ZeroMemory(publicKeyBytes);
            return false;
        }

        try
        {
            var publicKey = PublicKey.Import(
                Algorithm,
                publicKeyBytes,
                KeyBlobFormat.RawPublicKey);
            return Algorithm.Verify(publicKey, message, signatureBytes);
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyBytes);
        }
    }

    /// <summary>
    /// Verify a lowercase hex signature string (64 bytes / 128 hex chars).
    /// </summary>
    public static bool VerifyHexSignature(
        string publicKeyHex,
        ReadOnlySpan<byte> message,
        string signatureHex)
    {
        if (!TryParseHexExact(signatureHex, SignatureLength, out var signature))
        {
            return false;
        }

        try
        {
            return VerifyHex(publicKeyHex, message, signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    /// <summary>Parse a 32-byte public key from hex (either case).</summary>
    public static bool TryParsePublicKey(string? publicKeyHex, out byte[] publicKeyBytes) =>
        TryParseHexExact(publicKeyHex, PublicKeyLength, out publicKeyBytes);

    /// <summary>
    /// Strict hex parse of exactly <paramref name="byteLength"/> bytes.
    /// Accepts uppercase or lowercase hex digits only.
    /// </summary>
    public static bool TryParseHexExact(string? hex, int byteLength, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (hex is null || hex.Length != byteLength * 2)
        {
            return false;
        }

        var buffer = new byte[byteLength];
        for (var i = 0; i < byteLength; i++)
        {
            if (!TryHexNibble(hex[i * 2], out var hi) || !TryHexNibble(hex[i * 2 + 1], out var lo))
            {
                return false;
            }

            buffer[i] = (byte)((hi << 4) | lo);
        }

        bytes = buffer;
        return true;
    }

    /// <summary>Lowercase hex encoding used on the v2 wire.</summary>
    public static string ToLowerHex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(bytes).ToLowerInvariant();

    private static bool TryHexNibble(char c, out int nibble)
    {
        if (c is >= '0' and <= '9')
        {
            nibble = c - '0';
            return true;
        }

        if (c is >= 'a' and <= 'f')
        {
            nibble = c - 'a' + 10;
            return true;
        }

        if (c is >= 'A' and <= 'F')
        {
            nibble = c - 'A' + 10;
            return true;
        }

        nibble = 0;
        return false;
    }

    private static string ExportPublicKeyHex(Key key)
    {
        var raw = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        try
        {
            return ToLowerHex(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed || _key is null, this);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _key?.Dispose();
            _key = null;
        }
    }

    /// <summary>Never expose key material through diagnostics.</summary>
    public override string ToString() => "Ed25519DeviceKey";
}
