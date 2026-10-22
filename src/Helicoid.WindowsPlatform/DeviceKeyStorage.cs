using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Helicoid.Domain.Client;
using Helicoid.WindowsPlatform.Native;
using Microsoft.Win32.SafeHandles;

namespace Helicoid.WindowsPlatform;

/// <summary>Result of a device-key storage operation.</summary>
public enum DeviceKeyStorageResult
{
    Success = 0,
    NotFound = 1,
    Corrupted = 2,
    DecryptionFailed = 3,
    EncryptionFailed = 4,
    IoError = 5,
    Forgotten = 6,
    AlreadyExists = 7,
    ReparsePointRefused = 8,
    OwnershipMismatch = 9,
}

/// <summary>
/// Persistent private manager device identity protected with current-user
/// Windows DPAPI in a product-owned per-user directory. On-disk format is
/// [4-byte version][4-byte plaintext length][DPAPI blob] with plaintext
/// "HSK1" + 32-byte seed + 32-byte public key.
///
/// Security properties:
/// - Unique create-new private temp; owned only after exclusive create succeeds;
///   never deletes pre-existing temp/link data.
/// - No-follow opens plus handle attribute and hardlink checks.
/// - Owner match and DACL ACE inspection on the opened file handle and the
///   product directory handle against the current process token user SID.
///   Broad untrusted principals (Everyone/Authenticated Users/...) must not
///   hold write-like rights.
/// - Validated parent directory handle is held across create/publish.
/// - Publish is atomic no-overwrite; a loser reopens the winner only on actual
///   AlreadyExists, never on arbitrary I/O failure.
/// - Forget deletes only a held, verified owned object via handle disposition.
/// - Seed/public ownership guard (derived public key must match stored public).
/// - Missing/corrupt state is never auto-recreated; Create never overwrites.
/// - No key material is logged, exported, or stringified.
/// </summary>
public sealed class DeviceKeyStorage : IDisposable
{
    private const uint CurrentVersion = 1;
    private const string StorageFileName = "device-identity.bin";
    private const int HeaderSize = 8;
    private const int PlainTextSize = 4 + 32 + 32; // magic + seed + public key
    private const int MaxTokenSidBytes = 256;

    private static readonly byte[] Magic = "HSK1"u8.ToArray();

    private readonly string _storageDirectory;
    private readonly string _storagePath;
    private bool _disposed;

    /// <summary>
    /// TEST-only per-instance barrier after real ancestors are pinned and
    /// immediately before product-directory creation. Not an authority
    /// override; production leaves this null.
    /// </summary>
    internal Action? BeforeDirectoryCreate;

    /// <summary>
    /// TEST-only per-instance barrier after real create/open handles are
    /// acquired and before leaf mutation or read/publish. Not an authority
    /// override; production leaves this null.
    /// </summary>
    internal Action? BeforeLeafMutate;

    public DeviceKeyStorage(string productDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(productDirectory);
        _storageDirectory = productDirectory;
        _storagePath = Path.Combine(productDirectory, StorageFileName);
    }

    public string StoragePath => _storagePath;

    public bool Exists()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return File.Exists(_storagePath);
    }

    /// <summary>
    /// Create a new persistent device key. Generates a fresh Ed25519 seed,
    /// derives the public key, encrypts both with current-user DPAPI, and
    /// publishes atomically without overwriting. The returned seed buffer must
    /// be zeroed by the caller after importing into a signing key.
    /// </summary>
    public DeviceKeyStorageResult CreateNew(out byte[] seed, out byte[] publicKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        seed = Array.Empty<byte>();
        publicKey = Array.Empty<byte>();

        if (File.Exists(_storagePath))
        {
            return DeviceKeyStorageResult.AlreadyExists;
        }

        // Pin ancestors first, then create/validate the product directory with
        // private ACL at creation. No mutation before the chain is held.
        var dirCheck = OpenOrCreateOwnedDirectory();
        if (dirCheck.Result != DeviceKeyStorageResult.Success)
        {
            DisposeHeld(dirCheck.Ancestors);
            return dirCheck.Result;
        }

        var ancestorsHeld = dirCheck.Ancestors;
        using var dirHandle = dirCheck.Handle!;
        if (!TryGetFileId(dirHandle.DangerousGetHandle(), out var dirFileIndex))
        {
            DisposeHeld(ancestorsHeld);
            return DeviceKeyStorageResult.IoError;
        }

        // Real handles are acquired; test barrier before leaf mutation/publish.
        BeforeLeafMutate?.Invoke();

        byte[] createdSeed = new byte[32];
        byte[] createdPublic = new byte[32];
        byte[]? plaintext = null;
        byte[]? encrypted = null;
        SafeFileHandle? ownedTempHandle = null;
        string? ownedTempPath = null;
        try
        {
            RandomNumberGenerator.Fill(createdSeed);
            if (!TryDerivePublicKey(createdSeed, createdPublic))
            {
                return DeviceKeyStorageResult.EncryptionFailed;
            }

            plaintext = BuildPlainBytes(createdSeed, createdPublic);
            if (!TryDpapiProtect(plaintext, out encrypted) || encrypted is null)
            {
                return DeviceKeyStorageResult.EncryptionFailed;
            }

            byte[] fileBytes = new byte[HeaderSize + encrypted.Length];
            BitConverter.TryWriteBytes(fileBytes.AsSpan(0, 4), CurrentVersion);
            BitConverter.TryWriteBytes(fileBytes.AsSpan(4, 4), plaintext.Length);
            Buffer.BlockCopy(encrypted, 0, fileBytes, HeaderSize, encrypted.Length);

            // Unique create-new private temp. Mark owned only after exclusive
            // create succeeds; never delete a pre-existing path.
            var tempPath = Path.Combine(
                _storageDirectory,
                $"device-identity.{Guid.NewGuid():N}.tmp");

            if (!TryGetCurrentUserSidPtr(out var creatorSid, out var creatorSidBuffer))
            {
                return DeviceKeyStorageResult.OwnershipMismatch;
            }

            IntPtr privateSd = IntPtr.Zero;
            try
            {
                if (!TryCreatePrivateSecurityDescriptor(creatorSid, out privateSd))
                {
                    return DeviceKeyStorageResult.OwnershipMismatch;
                }

                var sa = new SecurityAttributes
                {
                    nLength = Marshal.SizeOf<SecurityAttributes>(),
                    lpSecurityDescriptor = privateSd,
                    bInheritHandle = 0,
                };

                ownedTempHandle = FileSecurityNative.CreateFileWithSecurity(
                    tempPath,
                    FileSecurityNative.GenericWrite
                        | FileSecurityNative.ReadControl
                        | FileSecurityNative.WriteDac
                        | FileSecurityNative.Delete,
                    0, // exclusive
                    ref sa,
                    FileSecurityNative.CreateNew,
                    FileSecurityNative.FileFlagOpenReparsePoint | FileSecurityNative.FileFlagWriteThrough,
                    IntPtr.Zero);
            }
            finally
            {
                if (privateSd != IntPtr.Zero)
                {
                    Kernel32Native.LocalFree(privateSd);
                }

                if (creatorSidBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(creatorSidBuffer);
                }
            }

            if (ownedTempHandle.IsInvalid)
            {
                ownedTempHandle.Dispose();
                ownedTempHandle = null;
                return DeviceKeyStorageResult.IoError;
            }

            // Exclusive create succeeded: this temp is ours to clean up.
            ownedTempPath = tempPath;

            // Defense in depth: re-assert protected DACL on the held handle.
            if (!TryGetCurrentUserSidPtr(out var aclSid, out var aclSidBuffer))
            {
                return DeviceKeyStorageResult.OwnershipMismatch;
            }

            try
            {
                if (!TryApplyPrivateAclToHandle(ownedTempHandle, aclSid))
                {
                    return DeviceKeyStorageResult.OwnershipMismatch;
                }
            }
            finally
            {
                if (aclSidBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(aclSidBuffer);
                }
            }

            try
            {
                using (var fs = new FileStream(ownedTempHandle, FileAccess.Write, bufferSize: 4096, isAsync: false))
                {
                    fs.Write(fileBytes, 0, fileBytes.Length);
                    fs.Flush(true);
                }
            }
            catch (IOException)
            {
                return DeviceKeyStorageResult.IoError;
            }
            catch (UnauthorizedAccessException)
            {
                return DeviceKeyStorageResult.IoError;
            }
            finally
            {
                // FileStream disposal also disposes the handle; drop our ref.
                ownedTempHandle = null;
            }

            // Re-validate the held parent directory before publish (TOCTOU).
            if (!TryGetFileId(dirHandle.DangerousGetHandle(), out var dirIndexNow)
                || dirIndexNow != dirFileIndex
                || !IsStillOwnedDirectory(dirHandle.DangerousGetHandle()))
            {
                return DeviceKeyStorageResult.OwnershipMismatch;
            }

            // Atomic no-overwrite publish.
            try
            {
                File.Move(ownedTempPath, _storagePath, overwrite: false);
                ownedTempPath = null;
            }
            catch (IOException ex)
            {
                // Loser of a true publish race reopens the validated winner
                // only when the destination already exists; other I/O fails closed.
                if (IsAlreadyExists(ex) && File.Exists(_storagePath))
                {
                    return DeviceKeyStorageResult.AlreadyExists;
                }

                return DeviceKeyStorageResult.IoError;
            }
            catch (UnauthorizedAccessException)
            {
                return DeviceKeyStorageResult.IoError;
            }

            seed = createdSeed;
            publicKey = createdPublic;
            createdSeed = Array.Empty<byte>();
            createdPublic = Array.Empty<byte>();
            return DeviceKeyStorageResult.Success;
        }
        catch (CryptographicException)
        {
            return DeviceKeyStorageResult.EncryptionFailed;
        }
        finally
        {
            DisposeHeld(ancestorsHeld);
            ownedTempHandle?.Dispose();
            if (createdSeed.Length > 0)
            {
                CryptographicOperations.ZeroMemory(createdSeed);
            }

            if (createdPublic.Length > 0)
            {
                CryptographicOperations.ZeroMemory(createdPublic);
            }

            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            if (encrypted is not null)
            {
                CryptographicOperations.ZeroMemory(encrypted);
            }

            if (ownedTempPath is not null)
            {
                // Only a path this call exclusively created is deleted.
                TryDeleteOwnedFile(ownedTempPath);
            }
        }
    }

    /// <summary>
    /// Open existing device-key state. Verifies handle ownership/DACL,
    /// no-follow link refusal, and the seed/public ownership guard.
    /// </summary>
    public DeviceKeyStorageResult Open(out byte[] seed, out byte[] publicKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        seed = Array.Empty<byte>();
        publicKey = Array.Empty<byte>();

        if (!File.Exists(_storagePath))
        {
            return DeviceKeyStorageResult.NotFound;
        }

        // Pin ancestors and verify the product directory (owner/private ACL)
        // before the leaf read; ancestors stay held across OpenLeaf.
        var dirCheck = OpenVerifiedOwnedDirectory();
        if (dirCheck.Result != DeviceKeyStorageResult.Success)
        {
            DisposeHeld(dirCheck.Ancestors);
            return dirCheck.Result;
        }

        using var productDir = dirCheck.Handle!;
        try
        {
            return OpenLeaf(ref seed, ref publicKey, dirCheck.Ancestors);
        }
        finally
        {
            DisposeHeld(dirCheck.Ancestors);
        }
    }

    private DeviceKeyStorageResult OpenLeaf(ref byte[] seed, ref byte[] publicKey, List<SafeFileHandle> _)
    {
        // Read access is required for FileStream reads (FILE_READ_DATA).
        var handleCheck = OpenOwnedFile(
            _storagePath,
            FileSecurityNative.FileReadData | FileSecurityNative.FileReadAttributes
                | FileSecurityNative.ReadControl | FileSecurityNative.Synchronize,
            forDelete: false);
        if (handleCheck.Result != DeviceKeyStorageResult.Success)
        {
            return handleCheck.Result;
        }

        using var handle = handleCheck.Handle!;

        // Real leaf handle acquired; test barrier before read.
        BeforeLeafMutate?.Invoke();

        try
        {
            using var fs = new FileStream(handle, FileAccess.Read, bufferSize: 4096, isAsync: false);

            byte[] header = new byte[HeaderSize];
            if (fs.Read(header, 0, HeaderSize) < HeaderSize)
            {
                return DeviceKeyStorageResult.Corrupted;
            }

            uint version = BitConverter.ToUInt32(header, 0);
            if (version != CurrentVersion)
            {
                return DeviceKeyStorageResult.Corrupted;
            }

            int plaintextLen = BitConverter.ToInt32(header, 4);
            if (plaintextLen != PlainTextSize)
            {
                return DeviceKeyStorageResult.Corrupted;
            }

            long blobLen = fs.Length - HeaderSize;
            if (blobLen <= 0 || blobLen > DpapiNative.MaxEncryptedBlobBytes)
            {
                return DeviceKeyStorageResult.Corrupted;
            }

            byte[] encryptedBlob = new byte[blobLen];
            if (fs.Read(encryptedBlob, 0, (int)blobLen) < blobLen)
            {
                return DeviceKeyStorageResult.Corrupted;
            }

            if (!TryDpapiUnprotect(encryptedBlob, out byte[]? plaintext) || plaintext is null)
            {
                return DeviceKeyStorageResult.DecryptionFailed;
            }

            try
            {
                if (plaintext.Length != PlainTextSize)
                {
                    return DeviceKeyStorageResult.Corrupted;
                }

                if (!plaintext.AsSpan(0, 4).SequenceEqual(Magic))
                {
                    return DeviceKeyStorageResult.OwnershipMismatch;
                }

                var openedSeed = plaintext.AsSpan(4, 32).ToArray();
                var openedPublic = plaintext.AsSpan(36, 32).ToArray();
                var derived = new byte[32];
                var deriveOk = TryDerivePublicKey(openedSeed, derived);
                if (!deriveOk || !derived.AsSpan().SequenceEqual(openedPublic))
                {
                    CryptographicOperations.ZeroMemory(openedSeed);
                    CryptographicOperations.ZeroMemory(openedPublic);
                    CryptographicOperations.ZeroMemory(derived);
                    return DeviceKeyStorageResult.OwnershipMismatch;
                }

                CryptographicOperations.ZeroMemory(derived);
                seed = openedSeed;
                publicKey = openedPublic;
                return DeviceKeyStorageResult.Success;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (IOException)
        {
            return DeviceKeyStorageResult.IoError;
        }
        catch (UnauthorizedAccessException)
        {
            return DeviceKeyStorageResult.IoError;
        }
    }

    /// <summary>
    /// Open the persistent identity or create it exactly once. Concurrent
    /// create races resolve to a single winner; the loser reads the winner's
    /// identity only after an actual AlreadyExists result.
    /// </summary>
    public DeviceKeyStorageResult OpenOrCreate(out byte[] seed, out byte[] publicKey)
    {
        var open = Open(out seed, out publicKey);
        if (open != DeviceKeyStorageResult.NotFound)
        {
            return open;
        }

        var created = CreateNew(out seed, out publicKey);
        if (created != DeviceKeyStorageResult.AlreadyExists)
        {
            return created;
        }

        return Open(out seed, out publicKey);
    }

    /// <summary>
    /// Delete the owned device-key file only via a held, verified handle
    /// disposition. Fails closed when the object cannot be validated.
    /// </summary>
    public DeviceKeyStorageResult Forget()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!File.Exists(_storagePath))
        {
            return DeviceKeyStorageResult.NotFound;
        }

        // Product-private parent contract applies to removal: pin+verify the
        // product directory before leaf disposition; ancestors stay held.
        var dirCheck = OpenVerifiedOwnedDirectory();
        if (dirCheck.Result != DeviceKeyStorageResult.Success)
        {
            DisposeHeld(dirCheck.Ancestors);
            return dirCheck.Result;
        }

        using var productDir = dirCheck.Handle!;
        try
        {
            return ForgetLeaf(dirCheck.Ancestors);
        }
        finally
        {
            DisposeHeld(dirCheck.Ancestors);
        }
    }

    private DeviceKeyStorageResult ForgetLeaf(List<SafeFileHandle> _)
    {
        var handleCheck = OpenOwnedFile(
            _storagePath,
            FileSecurityNative.ReadControl | FileSecurityNative.Delete | FileSecurityNative.FileReadAttributes,
            forDelete: true);
        if (handleCheck.Result != DeviceKeyStorageResult.Success)
        {
            return handleCheck.Result;
        }

        using var handle = handleCheck.Handle!;
        try
        {
            // Handle-relative delete: no path TOCTOU after validation.
            var disposition = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteByte(disposition, 0, 1); // DeleteFile = TRUE
                if (!FileSecurityNative.SetFileInformationByHandle(
                        handle,
                        FileSecurityNative.FileDispositionInfo,
                        disposition,
                        1))
                {
                    return DeviceKeyStorageResult.IoError;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(disposition);
            }

            return DeviceKeyStorageResult.Forgotten;
        }
        catch (IOException)
        {
            return DeviceKeyStorageResult.IoError;
        }
        catch (UnauthorizedAccessException)
        {
            return DeviceKeyStorageResult.IoError;
        }
    }

    private static byte[] BuildPlainBytes(byte[] seed, byte[] publicKey)
    {
        var plain = new byte[PlainTextSize];
        Magic.CopyTo(plain.AsSpan(0, 4));
        seed.CopyTo(plain.AsSpan(4, 32));
        publicKey.CopyTo(plain.AsSpan(36, 32));
        return plain;
    }

    /// <summary>
    /// Derive the Ed25519 public key from a seed via NSec (real libsodium).
    /// Programming faults are not masked; only expected crypto failures map to false.
    /// </summary>
    private static bool TryDerivePublicKey(byte[] seed, byte[] publicKey)
    {
        if (seed.Length != 32 || publicKey.Length != 32)
        {
            return false;
        }

        try
        {
            using var key = Helicoid.Domain.Client.Ed25519DeviceKey.ImportSeed(seed);
            return CopyPublicKey(key.PublicKeyHex, publicKey);
        }
        catch (ServerClientException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool CopyPublicKey(string publicKeyHex, byte[] destination)
    {
        if (!Helicoid.Domain.Client.Ed25519DeviceKey.TryParsePublicKey(publicKeyHex, out var raw)
            || raw.Length != destination.Length)
        {
            return false;
        }

        raw.CopyTo(destination.AsSpan());
        return true;
    }

    /// <summary>
    /// Pin ancestors (junctions refused) first, then create the product
    /// directory if missing with a private DACL, or validate an existing one
    /// without re-ACLing it. Returns the held product-directory handle.
    /// </summary>
    private (DeviceKeyStorageResult Result, SafeFileHandle? Handle, List<SafeFileHandle> Ancestors)
        OpenOrCreateOwnedDirectory()
    {
        string fullDir = Path.GetFullPath(_storageDirectory);
        var ancestors = OpenAncestorChain(fullDir, includeLeaf: false, leafIsDirectory: true);
        if (ancestors.Result != DeviceKeyStorageResult.Success)
        {
            return (ancestors.Result, null, ancestors.Held);
        }

        if (!Directory.Exists(_storageDirectory))
        {
            BeforeDirectoryCreate?.Invoke();

            if (!TryGetCurrentUserSidPtr(out var userSid, out var userSidBuffer))
            {
                DisposeHeld(ancestors.Held);
                return (DeviceKeyStorageResult.OwnershipMismatch, null, new List<SafeFileHandle>());
            }

            try
            {
                if (!TryCreatePrivateSecurityDescriptor(userSid, out IntPtr sd))
                {
                    DisposeHeld(ancestors.Held);
                    return (DeviceKeyStorageResult.OwnershipMismatch, null, new List<SafeFileHandle>());
                }

                try
                {
                    var sa = new SecurityAttributes
                    {
                        nLength = Marshal.SizeOf<SecurityAttributes>(),
                        lpSecurityDescriptor = sd,
                        bInheritHandle = 0,
                    };
                    if (!FileSecurityNative.CreateDirectoryW(_storageDirectory, ref sa))
                    {
                        int createError = Marshal.GetLastWin32Error();
                        // ERROR_ALREADY_EXISTS (183) / ERROR_FILE_EXISTS (80):
                        // a concurrent legitimate creator won the directory
                        // race. Reopen and validate the winner below. Any other
                        // create failure is not a race and fails closed.
                        if (createError is not (183 or 80))
                        {
                            DisposeHeld(ancestors.Held);
                            return (DeviceKeyStorageResult.IoError, null, new List<SafeFileHandle>());
                        }

                        // Fall through: validate the winner without re-ACLing.
                    }
                }
                finally
                {
                    Kernel32Native.LocalFree(sd);
                }
            }
            finally
            {
                if (userSidBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(userSidBuffer);
                }
            }
        }

        // Existing directories are validated, never re-ACLed.
        var dir = OpenOwnedFile(
            _storageDirectory,
            FileSecurityNative.FileListDirectory | FileSecurityNative.FileReadAttributes
                | FileSecurityNative.ReadControl | FileSecurityNative.Synchronize,
            forDelete: false,
            isDirectory: true);
        if (dir.Result != DeviceKeyStorageResult.Success)
        {
            DisposeHeld(ancestors.Held);
            return (dir.Result, null, new List<SafeFileHandle>());
        }

        return (DeviceKeyStorageResult.Success, dir.Handle, ancestors.Held);
    }

    /// <summary>
    /// Open a no-follow handle and verify link refusal plus owner/DACL
    /// ownership against the current process token user SID.
    /// Share mode omits FILE_SHARE_DELETE so the held object cannot be
    /// renamed/replaced while this operation owns it.
    /// </summary>
    private static (DeviceKeyStorageResult Result, SafeFileHandle? Handle) OpenOwnedFile(
        string path,
        uint desiredAccess,
        bool forDelete,
        bool isDirectory = false)
    {
        uint flags = FileSecurityNative.FileFlagOpenReparsePoint;
        if (isDirectory)
        {
            flags |= FileSecurityNative.FileFlagBackupSemantics;
        }

        // No FILE_SHARE_DELETE: pin the pathname against rename/replacement.
        var handle = FileSecurityNative.CreateFileW(
            path,
            desiredAccess,
            FileSecurityNative.FileShareRead | FileSecurityNative.FileShareWrite,
            IntPtr.Zero,
            FileSecurityNative.OpenExisting,
            flags,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            handle.Dispose();
            return (DeviceKeyStorageResult.IoError, null);
        }

        // Handle-level reparse/hardlink refusal (covers TOCTOU on FileInfo).
        if (!Kernel32Native.GetFileInformationByHandle(handle.DangerousGetHandle(), out var info))
        {
            handle.Dispose();
            return (DeviceKeyStorageResult.IoError, null);
        }

        if ((info.dwFileAttributes & FileSecurityNative.FileAttributeReparsePoint) != 0
            || info.nNumberOfLinks > 1)
        {
            handle.Dispose();
            return (DeviceKeyStorageResult.ReparsePointRefused, null);
        }

        var owner = VerifyHandleOwnedByCurrentUser(handle.DangerousGetHandle());
        if (owner != DeviceKeyStorageResult.Success)
        {
            handle.Dispose();
            return (owner, null);
        }

        return (DeviceKeyStorageResult.Success, handle);
    }

    /// <summary>
    /// Pin ancestors (junctions refused) and open the existing product
    /// directory with owner/DACL verification. Does not create or re-ACL.
    /// Used by Open/Forget so the product-private parent contract applies to
    /// reads and removals, not only create. Ancestors stay held for the caller.
    /// </summary>
    private (DeviceKeyStorageResult Result, SafeFileHandle? Handle, List<SafeFileHandle> Ancestors)
        OpenVerifiedOwnedDirectory()
    {
        string fullDir = Path.GetFullPath(_storageDirectory);
        var ancestors = OpenAncestorChain(fullDir, includeLeaf: false, leafIsDirectory: true);
        if (ancestors.Result != DeviceKeyStorageResult.Success)
        {
            return (ancestors.Result, null, ancestors.Held);
        }

        var dir = OpenOwnedFile(
            _storageDirectory,
            FileSecurityNative.FileListDirectory | FileSecurityNative.FileReadAttributes
                | FileSecurityNative.ReadControl | FileSecurityNative.Synchronize,
            forDelete: false,
            isDirectory: true);
        if (dir.Result != DeviceKeyStorageResult.Success)
        {
            DisposeHeld(ancestors.Held);
            return (dir.Result, null, new List<SafeFileHandle>());
        }

        return (DeviceKeyStorageResult.Success, dir.Handle, ancestors.Held);
    }

    /// <summary>
    /// Open and hold every intermediate path component with no-follow.
    /// Refuses any reparse point in the chain (junction/symlink parents).
    /// Ownership/DACL is strict on the product directory and leaf only;
    /// ancestors are pinned (no FILE_SHARE_DELETE) without re-ACLing them.
    /// On any failure the chain this call acquired is disposed here (common
    /// owner); the caller receives an empty list and never a partial hold.
    /// </summary>
    private static (DeviceKeyStorageResult Result, List<SafeFileHandle> Held)
        OpenAncestorChain(string fullPath, bool includeLeaf, bool leafIsDirectory)
    {
        var held = new List<SafeFileHandle>();
        var transferred = false;
        try
        {
            string root = Path.GetPathRoot(fullPath) ?? string.Empty;
            string relative = fullPath.Length > root.Length ? fullPath[root.Length..] : string.Empty;
            var parts = relative.Split(
                new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                StringSplitOptions.RemoveEmptyEntries);

            string current = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            for (int i = 0; i < parts.Length; i++)
            {
                bool isLeaf = i == parts.Length - 1;
                if (isLeaf && !includeLeaf)
                {
                    break;
                }

                current = Path.Combine(current, parts[i]);
                bool isDirectory = !isLeaf || leafIsDirectory;

                uint flags = FileSecurityNative.FileFlagOpenReparsePoint;
                if (isDirectory)
                {
                    flags |= FileSecurityNative.FileFlagBackupSemantics;
                }

                // Owner/DACL verification needs READ_CONTROL on the opened
                // handle. Leaf is fully owned-checked, so it must request it.
                // Share mode still omits FILE_SHARE_DELETE (NoShareDelete).
                uint desiredAccess = isDirectory
                    ? FileSecurityNative.FileListDirectory | FileSecurityNative.FileReadAttributes
                    : FileSecurityNative.FileReadData | FileSecurityNative.FileReadAttributes;
                if (isLeaf)
                {
                    desiredAccess |= FileSecurityNative.ReadControl;
                }

                // Intermediate components are pinned without share-delete and
                // must not be reparse points. Leaf is fully owned-checked.
                var handle = FileSecurityNative.CreateFileW(
                    current,
                    desiredAccess,
                    FileSecurityNative.FileShareRead | FileSecurityNative.FileShareWrite,
                    IntPtr.Zero,
                    FileSecurityNative.OpenExisting,
                    flags,
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    handle.Dispose();
                    return (DeviceKeyStorageResult.IoError, held);
                }

                if (!Kernel32Native.GetFileInformationByHandle(handle.DangerousGetHandle(), out var info))
                {
                    handle.Dispose();
                    return (DeviceKeyStorageResult.IoError, held);
                }

                if ((info.dwFileAttributes & FileSecurityNative.FileAttributeReparsePoint) != 0)
                {
                    handle.Dispose();
                    return (DeviceKeyStorageResult.ReparsePointRefused, held);
                }

                if (isLeaf)
                {
                    if (info.nNumberOfLinks > 1)
                    {
                        handle.Dispose();
                        return (DeviceKeyStorageResult.ReparsePointRefused, held);
                    }

                    var owner = VerifyHandleOwnedByCurrentUser(handle.DangerousGetHandle());
                    if (owner != DeviceKeyStorageResult.Success)
                    {
                        handle.Dispose();
                        return (owner, held);
                    }
                }

                held.Add(handle);
            }

            transferred = true;
            return (DeviceKeyStorageResult.Success, held);
        }
        catch (IOException)
        {
            return (DeviceKeyStorageResult.IoError, held);
        }
        catch (UnauthorizedAccessException)
        {
            return (DeviceKeyStorageResult.IoError, held);
        }
        finally
        {
            // Common owner: never leak a partial chain on failure exits.
            if (!transferred)
            {
                DisposeHeld(held);
                held.Clear();
            }
        }
    }

    private static bool IsStillOwnedDirectory(IntPtr dirHandle) =>
        VerifyHandleOwnedByCurrentUser(dirHandle) == DeviceKeyStorageResult.Success;

    private static bool TryGetFileId(IntPtr handle, out ulong fileIndex)
    {
        fileIndex = 0;
        if (!Kernel32Native.GetFileInformationByHandle(handle, out var info))
        {
            return false;
        }

        fileIndex = ((ulong)info.nFileIndexHigh << 32) | info.nFileIndexLow;
        return info.nFileIndexHigh != 0 || info.nFileIndexLow != 0;
    }

    /// <summary>
    /// Owner must be the current process token user SID and the DACL must be
    /// present with only allowlisted principals. Fail closed when identity or
    /// ACL contents cannot be established.
    /// </summary>
    private static DeviceKeyStorageResult VerifyHandleOwnedByCurrentUser(IntPtr fileHandle)
    {
        if (!TryGetCurrentUserSidPtr(out var userSid, out var userSidBuffer))
        {
            return DeviceKeyStorageResult.OwnershipMismatch;
        }

        IntPtr securityDescriptor = IntPtr.Zero;
        try
        {
            var status = FileSecurityNative.GetSecurityInfo(
                fileHandle,
                FileSecurityNative.SeFileObject,
                FileSecurityNative.OwnerSecurityInformation | FileSecurityNative.DaclSecurityInformation,
                out IntPtr pSidOwner,
                out _,
                out IntPtr pDacl,
                out _,
                out securityDescriptor);

            if (status != FileSecurityNative.ErrorSuccess)
            {
                return DeviceKeyStorageResult.OwnershipMismatch;
            }

            if (pSidOwner == IntPtr.Zero
                || !FileSecurityNative.IsValidSid(pSidOwner)
                || !FileSecurityNative.EqualSid(pSidOwner, userSid))
            {
                return DeviceKeyStorageResult.OwnershipMismatch;
            }

            if (pDacl == IntPtr.Zero)
            {
                return DeviceKeyStorageResult.OwnershipMismatch;
            }

            if (!IsDaclAcceptableForPrivateKey(pDacl, userSid))
            {
                return DeviceKeyStorageResult.OwnershipMismatch;
            }

            return DeviceKeyStorageResult.Success;
        }
        finally
        {
            if (securityDescriptor != IntPtr.Zero)
            {
                Kernel32Native.LocalFree(securityDescriptor);
            }

            if (userSidBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(userSidBuffer);
            }
        }
    }

    /// <summary>
    /// ACL_SIZE_INFORMATION layout (winnt.h):
    /// AceCount @0, AclBytesInUse @4, AclBytesFree @8.
    /// Trusted-principal allowlist only.
    /// </summary>
    private static bool IsDaclAcceptableForPrivateKey(IntPtr pDacl, IntPtr userSid)
    {
        var aclInfo = Marshal.AllocHGlobal(12);
        try
        {
            if (!FileSecurityNative.GetAclInformation(
                    pDacl,
                    aclInfo,
                    12,
                    FileSecurityNative.AclSizeInformation))
            {
                return false;
            }

            int aceCount = Marshal.ReadInt32(aclInfo, 0);
            int aclBytesInUse = Marshal.ReadInt32(aclInfo, 4);
            if (aceCount < 0
                || aceCount > FileSecurityNative.MaxInspectedAceCount
                || aclBytesInUse <= 0
                || aclBytesInUse > 64 * 1024)
            {
                return false;
            }

            for (int i = 0; i < aceCount; i++)
            {
                if (!FileSecurityNative.GetAce(pDacl, (uint)i, out IntPtr pAce) || pAce == IntPtr.Zero)
                {
                    return false;
                }

                byte aceType = Marshal.ReadByte(pAce, 0);
                if (aceType == FileSecurityNative.AccessDeniedAceType)
                {
                    continue;
                }

                if (aceType != FileSecurityNative.AccessAllowedAceType)
                {
                    return false;
                }

                IntPtr pSid = IntPtr.Add(pAce, 8);
                if (!FileSecurityNative.IsValidSid(pSid))
                {
                    return false;
                }

                if (!IsTrustedPrincipal(pSid, userSid))
                {
                    return false;
                }
            }

            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(aclInfo);
        }
    }

    private static bool IsTrustedPrincipal(IntPtr pSid, IntPtr userSid)
    {
        if (userSid != IntPtr.Zero
            && FileSecurityNative.IsValidSid(pSid)
            && FileSecurityNative.IsValidSid(userSid)
            && FileSecurityNative.EqualSid(pSid, userSid))
        {
            return true;
        }

        if (!FileSecurityNative.ConvertSidToStringSidW(pSid, out IntPtr pString))
        {
            return false;
        }

        string sid;
        try
        {
            sid = Marshal.PtrToStringUni(pString) ?? string.Empty;
        }
        finally
        {
            Kernel32Native.LocalFree(pString);
        }

        foreach (var trusted in FileSecurityNative.TrustedPrivilegedSidStrings)
        {
            if (string.Equals(sid, trusted, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Pin a private directory and its ancestors with the same
    /// ownership/reparse/no-share-delete rules used by create/open.
    /// </summary>
    internal static DeviceKeyStorageResult TryPinDirectory(string directory, out IDisposable? pin)
    {
        pin = null;
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return DeviceKeyStorageResult.NotFound;
        }

        string full = Path.GetFullPath(directory);
        var ancestors = OpenAncestorChain(full, includeLeaf: true, leafIsDirectory: true);
        if (ancestors.Result != DeviceKeyStorageResult.Success)
        {
            DisposeHeld(ancestors.Held);
            return ancestors.Result;
        }

        pin = new DirectoryPin(ancestors.Held);
        return DeviceKeyStorageResult.Success;
    }

    private sealed class DirectoryPin : IDisposable
    {
        private List<SafeFileHandle>? _held;

        public DirectoryPin(List<SafeFileHandle> held) => _held = held;

        public void Dispose()
        {
            var held = Interlocked.Exchange(ref _held, null);
            if (held is not null)
            {
                DisposeHeld(held);
            }
        }
    }

    private static void DisposeHeld(List<SafeFileHandle> held)
    {
        foreach (var h in held)
        {
            try { h.Dispose(); } catch { /* cleanup */ }
        }
    }

    /// <summary>
    /// Apply a protected private DACL on a held handle:
    /// PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION.
    /// Never requests SACL (requires privilege the user lacks).
    /// </summary>
    private static bool TryApplyPrivateAclToHandle(SafeFileHandle handle, IntPtr userSid)
    {
        if (userSid == IntPtr.Zero || !FileSecurityNative.IsValidSid(userSid))
        {
            return false;
        }

        if (!FileSecurityNative.ConvertSidToStringSidW(userSid, out IntPtr pString))
        {
            return false;
        }

        string userSidString;
        try
        {
            userSidString = Marshal.PtrToStringUni(pString) ?? string.Empty;
        }
        finally
        {
            Kernel32Native.LocalFree(pString);
        }

        if (userSidString.Length == 0)
        {
            return false;
        }

        // Private, non-inherited DACL: current user full control only.
        var sddl = "O:" + userSidString + "G:" + userSidString + "D:P(A;;FA;;;" + userSidString + ")";
        if (!FileSecurityNative.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                FileSecurityNative.SecurityDescriptorRevision,
                out IntPtr sd,
                out _))
        {
            return false;
        }

        try
        {
            if (!FileSecurityNative.GetSecurityDescriptorDacl(sd, out bool daclPresent, out IntPtr pDacl, out _)
                || !daclPresent
                || pDacl == IntPtr.Zero)
            {
                return false;
            }

            // Correct flags: protect DACL, request DACL only — no SACL bit.
            var status = FileSecurityNative.SetSecurityInfo(
                handle,
                FileSecurityNative.SeFileObject,
                FileSecurityNative.DaclSecurityInformation
                    | FileSecurityNative.ProtectedDaclSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                pDacl,
                IntPtr.Zero);
            return status == FileSecurityNative.ErrorSuccess;
        }
        finally
        {
            Kernel32Native.LocalFree(sd);
        }
    }

    /// <summary>
    /// Build a self-relative private SD for object creation (SECURITY_ATTRIBUTES).
    /// Caller frees with LocalFree.
    /// </summary>
    private static bool TryCreatePrivateSecurityDescriptor(IntPtr userSid, out IntPtr sd)
    {
        sd = IntPtr.Zero;
        if (userSid == IntPtr.Zero || !FileSecurityNative.IsValidSid(userSid))
        {
            return false;
        }

        if (!FileSecurityNative.ConvertSidToStringSidW(userSid, out IntPtr pString))
        {
            return false;
        }

        string userSidString;
        try
        {
            userSidString = Marshal.PtrToStringUni(pString) ?? string.Empty;
        }
        finally
        {
            Kernel32Native.LocalFree(pString);
        }

        if (userSidString.Length == 0)
        {
            return false;
        }

        var sddl = "O:" + userSidString + "G:" + userSidString + "D:P(A;;FA;;;" + userSidString + ")";
        return FileSecurityNative.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            FileSecurityNative.SecurityDescriptorRevision,
            out sd,
            out _);
    }

    /// <summary>
    /// First GetTokenInformation probe is expected to fail with
    /// ERROR_INSUFFICIENT_BUFFER while reporting the required size.
    /// </summary>
    private static bool TryGetCurrentUserSidPtr(out IntPtr userSid, out IntPtr userSidBuffer)
    {
        userSid = IntPtr.Zero;
        userSidBuffer = IntPtr.Zero;

        IntPtr process = Kernel32Native.GetCurrentProcess();
        if (!FileSecurityNative.OpenProcessToken(process, FileSecurityNative.TokenQuery, out var token))
        {
            return false;
        }

        using (token)
        {
            var probeOk = FileSecurityNative.GetTokenInformation(
                token.DangerousGetHandle(),
                FileSecurityNative.TokenUser,
                IntPtr.Zero,
                0,
                out int needed);
            int probeError = Marshal.GetLastWin32Error();

            // Size probe: success is unexpected; failure must be INSUFFICIENT_BUFFER.
            if (probeOk)
            {
                return false;
            }

            if (probeError != FileSecurityNative.ErrorInsufficientBuffer
                || needed <= 0
                || needed > MaxTokenSidBytes)
            {
                return false;
            }

            userSidBuffer = Marshal.AllocHGlobal(needed);
            if (!FileSecurityNative.GetTokenInformation(
                    token.DangerousGetHandle(),
                    FileSecurityNative.TokenUser,
                    userSidBuffer,
                    needed,
                    out _))
            {
                Marshal.FreeHGlobal(userSidBuffer);
                userSidBuffer = IntPtr.Zero;
                return false;
            }

            userSid = Marshal.ReadIntPtr(userSidBuffer);
            return userSid != IntPtr.Zero && FileSecurityNative.IsValidSid(userSid);
        }
    }

    private static bool IsAlreadyExists(IOException ex) =>
        ex.HResult is unchecked((int)0x80070050) // ERROR_FILE_EXISTS
            or unchecked((int)0x800700B7)        // ERROR_ALREADY_EXISTS
        || ex.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains(
            "cannot create a file when that file already exists",
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Delete only a temp path this call exclusively created. Never deletes
    /// pre-existing temp/link data.
    /// </summary>
    private static void TryDeleteOwnedFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Cleanup must not throw.
        }
        catch (UnauthorizedAccessException)
        {
            // Cleanup must not throw.
        }
    }

    private static bool TryDpapiProtect(byte[] plaintext, out byte[]? encrypted)
    {
        encrypted = null;
        GCHandle plaintextHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
        try
        {
            var inputBlob = new DATA_BLOB
            {
                cbData = (uint)plaintext.Length,
                pbData = plaintextHandle.AddrOfPinnedObject(),
            };

            if (!DpapiNative.CryptProtectData(
                    ref inputBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    DpapiNative.CryptProtectUiForbidden,
                    out DATA_BLOB outputBlob))
            {
                return false;
            }

            try
            {
                encrypted = new byte[outputBlob.cbData];
                Marshal.Copy(outputBlob.pbData, encrypted, 0, (int)outputBlob.cbData);
                return true;
            }
            finally
            {
                Kernel32Native.LocalFree(outputBlob.pbData);
            }
        }
        finally
        {
            plaintextHandle.Free();
        }
    }

    private static bool TryDpapiUnprotect(byte[] ciphertext, out byte[]? plaintext)
    {
        plaintext = null;
        GCHandle ciphertextHandle = GCHandle.Alloc(ciphertext, GCHandleType.Pinned);
        try
        {
            var inputBlob = new DATA_BLOB
            {
                cbData = (uint)ciphertext.Length,
                pbData = ciphertextHandle.AddrOfPinnedObject(),
            };

            if (!DpapiNative.CryptUnprotectData(
                    ref inputBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    DpapiNative.CryptProtectUiForbidden,
                    out DATA_BLOB outputBlob))
            {
                return false;
            }

            try
            {
                plaintext = new byte[outputBlob.cbData];
                Marshal.Copy(outputBlob.pbData, plaintext, 0, (int)outputBlob.cbData);
                return true;
            }
            finally
            {
                Kernel32Native.LocalFree(outputBlob.pbData);
            }
        }
        finally
        {
            ciphertextHandle.Free();
        }
    }

    public void Dispose()
    {
        _disposed = true;
    }
}
