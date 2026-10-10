using System.Runtime.InteropServices;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// P/Invoke surface for Windows DPAPI (Data Protection API).
/// Used to protect enrollment state at rest with current-user scope.
///
/// Verified against Microsoft docs (October 2026):
/// CryptProtectData (wincrypt.h / Crypt32),
/// CryptUnprotectData (wincrypt.h / Crypt32),
/// LocalFree (winbase.h / Kernel32).
/// </summary>
public static class DpapiNative
{
    /// <summary>
    /// CRYPTPROTECT_UI_FORBIDDEN: suppress any UI prompt during protection.
    /// Enrollment is a background operation; no user interaction is acceptable.
    /// </summary>
    public const uint CryptProtectUiForbidden = 0x1;

    /// <summary>
    /// CRYPTPROTECT_AUDIT: generate an audit log entry on protect/unprotect.
    /// </summary>
    public const uint CryptProtectAudit = 0x10;

    /// <summary>
    /// CRYPTPROTECT_LOCAL_MACHINE: machine-scope protection. NOT used here;
    /// enrollment is per-user.
    /// </summary>
    public const uint CryptProtectLocalMachine = 0x4;

    /// <summary>
    /// Maximum encrypted blob size this module accepts. Prevents allocation
    /// attacks from corrupted storage files.
    /// </summary>
    public const int MaxEncryptedBlobBytes = 1024 * 1024; // 1 MiB

    /// <summary>
    /// Maximum plaintext secret bytes before encryption.
    /// </summary>
    public const int MaxPlaintextBytes = 512 * 1024; // 512 KiB

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        IntPtr szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        IntPtr szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);
}

/// <summary>
/// DATA_BLOB structure for DPAPI.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct DATA_BLOB
{
    public uint cbData;
    public IntPtr pbData;
}