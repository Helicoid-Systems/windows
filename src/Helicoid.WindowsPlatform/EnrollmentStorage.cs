using System.ComponentModel;
using System.Runtime.InteropServices;
using Helicoid.WindowsPlatform.Native;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Result of an enrollment storage operation.
/// </summary>
public enum EnrollmentStorageResult
{
    /// <summary>Operation succeeded.</summary>
    Success = 0,

    /// <summary>Enrollment state file does not exist.</summary>
    NotFound = 1,

    /// <summary>File exists but is corrupted or unreadable.</summary>
    Corrupted = 2,

    /// <summary>DPAPI decryption failed (wrong user, machine change, tampered blob).</summary>
    DecryptionFailed = 3,

    /// <summary>DPAPI encryption failed.</summary>
    EncryptionFailed = 4,

    /// <summary>File I/O error.</summary>
    IoError = 5,

    /// <summary>State explicitly forgotten (deleted).</summary>
    Forgotten = 6,

    /// <summary>Missing or corrupt state refused automatic recreation.</summary>
    RefusedAutoRecreation = 7,

    /// <summary>State already exists; Create refused to overwrite.</summary>
    AlreadyExists = 8,

    /// <summary>File is a reparse point or symbolic link (refused).</summary>
    ReparsePointRefused = 9,
}

/// <summary>
/// Manages portable enrollment local state protected with current-user DPAPI.
/// State is stored as a DPAPI-encrypted blob in a product-owned per-user
/// test directory. No private keys, logged usernames, SIDs, host paths, or
/// secrets appear in diagnostics.
///
/// The encrypted blob format is: [4-byte version][4-byte plaintext length][DPAPI blob].
/// Version must match <see cref="CurrentVersion"/> or the file is treated as corrupted.
///
/// Security properties:
/// - Bounded file read: reads version+length header first, then allocates exact blob size.
/// - Atomic write: writes to temp file, flushes, then renames (no partial writes).
/// - No overwrite: Create refuses to overwrite existing state.
/// - Reparse/link refusal: rejects symbolic links and reparse points.
/// - Temp buffer erasure: plaintext buffers are zeroed after use.
/// - Explicit first creation: missing/corrupt state never auto-rotates.
/// - Cleanup removes only the exact owned file, not arbitrary directories.
/// </summary>
public sealed class EnrollmentStorage : IDisposable
{
    private const uint CurrentVersion = 1;
    private const string StorageFileName = "enrollment-state.bin";
    private const string TempFileName = "enrollment-state.tmp";

    /// <summary>Maximum file size for the stored blob (header + encrypted data).</summary>
    private const int MaxFileBytes = DpapiNative.MaxEncryptedBlobBytes + 8;

    private readonly string _storageDirectory;
    private readonly string _storagePath;
    private readonly string _tempPath;
    private bool _disposed;

    /// <summary>
    /// Create an enrollment storage instance for the given product directory.
    /// </summary>
    /// <param name="productDirectory">Product-owned per-user directory.</param>
    public EnrollmentStorage(string productDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(productDirectory);

        _storageDirectory = productDirectory;
        _storagePath = Path.Combine(productDirectory, StorageFileName);
        _tempPath = Path.Combine(productDirectory, TempFileName);
    }

    /// <summary>
    /// The path to the enrollment state file.
    /// </summary>
    public string StoragePath => _storagePath;

    /// <summary>
    /// Check if enrollment state exists on disk.
    /// </summary>
    public bool Exists()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return File.Exists(_storagePath);
    }

    /// <summary>
    /// Open (read) existing enrollment state. Returns the decrypted bytes.
    /// If the file is missing or corrupt, returns <see cref="EnrollmentStorageResult.NotFound"/>
    /// or <see cref="EnrollmentStorageResult.Corrupted"/> without recreating state.
    ///
    /// Bounded read: reads version+length header first (8 bytes), then allocates
    /// exact blob size. Rejects reparse points and symbolic links.
    /// </summary>
    public EnrollmentStorageResult Open(out byte[]? secretBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        secretBytes = null;

        if (!File.Exists(_storagePath))
        {
            return EnrollmentStorageResult.NotFound;
        }

        // Reject reparse points, symbolic links, and hardlinks.
        if (IsReparsePointOrHardlink(_storagePath))
        {
            return EnrollmentStorageResult.ReparsePointRefused;
        }

        try
        {
            using var fs = new FileStream(_storagePath, FileMode.Open, FileAccess.Read, FileShare.None);

            // Bounded read: read header first (8 bytes).
            byte[] header = new byte[8];
            int headerRead = fs.Read(header, 0, 8);
            if (headerRead < 8)
            {
                return EnrollmentStorageResult.Corrupted;
            }

            uint version = BitConverter.ToUInt32(header, 0);
            if (version != CurrentVersion)
            {
                return EnrollmentStorageResult.Corrupted;
            }

            int plaintextLen = BitConverter.ToInt32(header, 4);
            if (plaintextLen < 0 || plaintextLen > DpapiNative.MaxPlaintextBytes)
            {
                return EnrollmentStorageResult.Corrupted;
            }

            // Calculate blob size from file length.
            long blobLen = fs.Length - 8;
            if (blobLen <= 0 || blobLen > DpapiNative.MaxEncryptedBlobBytes || blobLen > MaxFileBytes - 8)
            {
                return EnrollmentStorageResult.Corrupted;
            }

            // Allocate exact blob size and read.
            byte[] encryptedBlob = new byte[blobLen];
            int blobRead = fs.Read(encryptedBlob, 0, (int)blobLen);
            if (blobRead < blobLen)
            {
                return EnrollmentStorageResult.Corrupted;
            }

            // Decrypt with DPAPI.
            if (!TryDpapiUnprotect(encryptedBlob, out byte[]? decrypted) || decrypted is null)
            {
                // Erase any partial output.
                if (decrypted is not null)
                {
                    Array.Clear(decrypted);
                }
                return EnrollmentStorageResult.DecryptionFailed;
            }

            if (decrypted.Length != plaintextLen)
            {
                Array.Clear(decrypted);
                return EnrollmentStorageResult.Corrupted;
            }

            secretBytes = decrypted;
            return EnrollmentStorageResult.Success;
        }
        catch (IOException)
        {
            return EnrollmentStorageResult.IoError;
        }
        catch (UnauthorizedAccessException)
        {
            return EnrollmentStorageResult.IoError;
        }
    }

    /// <summary>
    /// Create (write) new enrollment state. Refuses to overwrite existing state.
    /// The plaintext bytes are encrypted with current-user DPAPI.
    /// Atomic write: writes to temp file, flushes, then renames.
    /// Erases plaintext temp buffers after encryption.
    /// </summary>
    public EnrollmentStorageResult Create(byte[] secretBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(secretBytes);

        if (secretBytes.Length > DpapiNative.MaxPlaintextBytes)
        {
            return EnrollmentStorageResult.EncryptionFailed;
        }

        // Refuse to overwrite existing state.
        if (File.Exists(_storagePath))
        {
            return EnrollmentStorageResult.AlreadyExists;
        }

        // Reject reparse points on the directory and parent path.
        if (IsReparsePointOrHardlink(_storageDirectory) || IsParentReparsePoint(_storagePath))
        {
            return EnrollmentStorageResult.ReparsePointRefused;
        }

        // Encrypt with DPAPI.
        byte[]? encrypted = null;
        try
        {
            if (!TryDpapiProtect(secretBytes, out encrypted) || encrypted is null)
            {
                return EnrollmentStorageResult.EncryptionFailed;
            }

            // Build file: [version][plaintext length][encrypted blob]
            byte[] fileBytes = new byte[8 + encrypted.Length];
            BitConverter.TryWriteBytes(fileBytes.AsSpan(0, 4), CurrentVersion);
            BitConverter.TryWriteBytes(fileBytes.AsSpan(4, 4), secretBytes.Length);
            Buffer.BlockCopy(encrypted, 0, fileBytes, 8, encrypted.Length);

            // Atomic write: temp file + flush + rename.
            Directory.CreateDirectory(_storageDirectory);

            // Clean up any leftover temp file.
            if (File.Exists(_tempPath))
            {
                File.Delete(_tempPath);
            }

            using (var fs = new FileStream(_tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(fileBytes, 0, fileBytes.Length);
                fs.Flush(true); // Force flush to disk.
            }

            // Atomic rename.
            File.Move(_tempPath, _storagePath, overwrite: false);

            return EnrollmentStorageResult.Success;
        }
        catch (IOException)
        {
            // Clean up temp file on failure.
            TryDeleteFile(_tempPath);
            return EnrollmentStorageResult.IoError;
        }
        catch (UnauthorizedAccessException)
        {
            TryDeleteFile(_tempPath);
            return EnrollmentStorageResult.IoError;
        }
        finally
        {
            // Erase encrypted temp buffer.
            if (encrypted is not null)
            {
                Array.Clear(encrypted);
            }
        }
    }

    /// <summary>
    /// Forget (delete) enrollment state. Removes only the exact owned file.
    /// Returns <see cref="EnrollmentStorageResult.Forgotten"/> on success.
    /// </summary>
    public EnrollmentStorageResult Forget()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!File.Exists(_storagePath))
        {
            return EnrollmentStorageResult.NotFound;
        }

        // Reject reparse points, symbolic links, and hardlinks.
        if (IsReparsePointOrHardlink(_storagePath))
        {
            return EnrollmentStorageResult.ReparsePointRefused;
        }

        try
        {
            File.Delete(_storagePath);
            // Also clean up any leftover temp file.
            TryDeleteFile(_tempPath);
            return EnrollmentStorageResult.Forgotten;
        }
        catch (IOException)
        {
            return EnrollmentStorageResult.IoError;
        }
        catch (UnauthorizedAccessException)
        {
            return EnrollmentStorageResult.IoError;
        }
    }

    /// <summary>
    /// Check if a path is a reparse point, symbolic link, or hardlink.
    /// Hardlinks are detected by checking the link count from the file handle.
    /// If the check fails, the path is refused (fail-closed).
    /// </summary>
    private static bool IsReparsePointOrHardlink(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return false;
            }

            // Check reparse point (covers symbolic links and mount points).
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return true;
            }

            // Check hardlink: open the file and inspect link count via kernel handle.
            return IsHardlink(path);
        }
        catch (Exception)
        {
            // If we can't check, refuse (fail-closed).
            return true;
        }
    }

    /// <summary>
    /// Check if a file is a hardlink by querying the kernel link count.
    /// Returns true if the file has more than one hard link, or if the check fails.
    /// </summary>
    private static bool IsHardlink(string path)
    {
        IntPtr handle = Kernel32Native.CreateFileW(
            path,
            0, // FILE_READ_ATTRIBUTES
            FileShare.Read | FileShare.Write | FileShare.Delete,
            IntPtr.Zero,
            3, // OPEN_EXISTING
            0,
            IntPtr.Zero);

        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            // Can't open — refuse (fail-closed).
            return true;
        }

        try
        {
            if (Kernel32Native.GetFileInformationByHandle(handle, out var fileInfo))
            {
                return fileInfo.nNumberOfLinks > 1;
            }

            // Can't query — refuse.
            return true;
        }
        finally
        {
            Kernel32Native.CloseHandle(handle);
        }
    }

    /// <summary>
    /// Check that the parent directory is not a reparse point.
    /// </summary>
    private static bool IsParentReparsePoint(string path)
    {
        try
        {
            string? parentDir = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(parentDir))
            {
                return false;
            }

            var dirInfo = new DirectoryInfo(parentDir);
            return dirInfo.Exists && dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint);
        }
        catch (Exception)
        {
            // If we can't check, refuse (fail-closed).
            return true;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception)
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