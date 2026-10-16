using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// P/Invoke surface for private-file owner/DACL verification and handle-relative
/// disposition. Declarations checked against Microsoft docs (October 2026):
/// GetSecurityInfo (aclapi.h) returns DWORD / ERROR_SUCCESS==0,
/// GetTokenInformation (securitybaseapi.h) returns BOOL and uses
/// ERROR_INSUFFICIENT_BUFFER for the size probe,
/// CreateFileW (fileapi.h), GetAce / GetAclInformation (aclapi.h),
/// SetFileInformationByHandle FileDispositionInfo (fileapi.h),
/// EqualSid / IsValidSid (securitybaseapi.h), LocalFree (winbase.h).
/// </summary>
public static class FileSecurityNative
{
    /// <summary>SE_FILE_OBJECT for GetSecurityInfo.</summary>
    public const uint SeFileObject = 1;

    public const uint OwnerSecurityInformation = 0x00000001;
    public const uint DaclSecurityInformation = 0x00000004;

    public const uint ReadControl = 0x00020000;
    public const uint Synchronize = 0x00100000;
    public const uint Delete = 0x00010000;
    public const uint WriteDac = 0x00040000;
    public const uint WriteOwner = 0x00080000;

    public const uint FileReadData = 0x0001;
    public const uint FileListDirectory = 0x0001;
    public const uint FileWriteData = 0x0002;
    public const uint FileAppendData = 0x0004;
    public const uint FileWriteEa = 0x0010;
    public const uint FileReadAttributes = 0x0080;
    public const uint FileWriteAttributes = 0x0100;

    public const uint FileShareRead = 0x00000001;
    public const uint FileShareWrite = 0x00000002;
    public const uint FileShareDelete = 0x00000004;
    public const uint CreateNew = 1;
    public const uint OpenExisting = 3;

    public const uint FileFlagOpenReparsePoint = 0x00200000;
    public const uint FileFlagBackupSemantics = 0x02000000;
    public const uint FileFlagWriteThrough = 0x80000000;

    public const uint FileAttributeReparsePoint = 0x0400;

    public const uint GenericRead = 0x80000000;
    public const uint GenericWrite = 0x40000000;
    public const uint GenericAll = 0x10000000;
    public const uint FileAllAccess = 0x001F01FF;

    /// <summary>ERROR_SUCCESS.</summary>
    public const int ErrorSuccess = 0;

    /// <summary>ERROR_INSUFFICIENT_BUFFER — expected from GetTokenInformation size probe.</summary>
    public const int ErrorInsufficientBuffer = 122;

    /// <summary>ACCESS_ALLOWED_ACE_TYPE.</summary>
    public const byte AccessAllowedAceType = 0;

    /// <summary>ACCESS_DENIED_ACE_TYPE.</summary>
    public const byte AccessDeniedAceType = 1;

    /// <summary>AclInformationClass: AclSizeInformation.</summary>
    /// <remarks>
    /// ACL_SIZE_INFORMATION (winnt.h) is
    /// { DWORD AceCount; DWORD AclBytesInUse; DWORD AclBytesFree }
    /// i.e. AceCount at offset 0, AclBytesInUse at 4, AclBytesFree at 8.
    /// </remarks>
    public const int AclSizeInformation = 2;

    /// <summary>FILE_INFO_BY_HANDLE_CLASS: FileDispositionInfo.</summary>
    public const int FileDispositionInfo = 4;

    /// <summary>Bound on DACL ACE count inspected before fail-closed refusal.</summary>
    public const int MaxInspectedAceCount = 64;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    /// <summary>CreateFileW overload with SECURITY_ATTRIBUTES for private-ACL creation.</summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    public static extern SafeFileHandle CreateFileWithSecurity(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        ref SecurityAttributes lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    /// <summary>
    /// Returns DWORD. Success is ERROR_SUCCESS (0); any other value is a Win32
    /// error code. Do not marshal as BOOL.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetSecurityInfo(
        IntPtr hHandle,
        uint objectType,
        uint securityInformation,
        out IntPtr pSidOwner,
        out IntPtr pSidGroup,
        out IntPtr pDacl,
        out IntPtr pSacl,
        out IntPtr ppSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsValidSid(IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetAce(IntPtr pAcl, uint dwAceIndex, out IntPtr pAce);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetAclInformation(
        IntPtr pAcl,
        IntPtr pAclInformation,
        int nAclInformationLength,
        int dwAclInformationClass);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeTokenHandle tokenHandle);

    /// <summary>
    /// BOOL return. The size probe (NULL, 0) is expected to fail with
    /// ERROR_INSUFFICIENT_BUFFER while setting ReturnLength.
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertSidToStringSidW(IntPtr pSid, out IntPtr stringSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        IntPtr lpFileInformation,
        uint dwBufferSize);

    public const int TokenUser = 1;
    public const uint TokenQuery = 0x0008;

    /// <summary>
    /// Privileged principals that may hold access on private key material
    /// alongside the current user. Matches the intended bounded system/admin
    /// exceptions only — not a blacklist of a few broad SIDs.
    /// </summary>
    public static readonly string[] TrustedPrivilegedSidStrings =
    [
        "S-1-5-18",     // NT AUTHORITY\SYSTEM
        "S-1-5-32-544", // BUILTIN\Administrators
        "S-1-3-0",      // CREATOR OWNER
    ];

    /// <summary>
    /// Write-like access mask bits that only allowlisted principals may hold.
    /// </summary>
    public const uint WriteLikeAccessMask =
        FileWriteData
        | FileAppendData
        | FileWriteEa
        | FileWriteAttributes
        | Delete
        | WriteDac
        | WriteOwner
        | GenericWrite
        | GenericAll
        | FileAllAccess;

    /// <summary>SECURITY_DESCRIPTOR_REVISION.</summary>
    public const uint SecurityDescriptorRevision = 1;

    /// <summary>PROTECTED_DACL_SECURITY_INFORMATION (winnt.h).</summary>
    public const uint ProtectedDaclSecurityInformation = 0x80000000;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor,
        uint stringSecurityDescriptorRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetSecurityDescriptorDacl(
        IntPtr pSecurityDescriptor,
        out bool lpbDaclPresent,
        out IntPtr pDacl,
        out bool lpbDaclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint SetNamedSecurityInfoW(
        string pObjectName,
        uint objectType,
        uint securityInformation,
        IntPtr psidOwner,
        IntPtr psidGroup,
        IntPtr pDacl,
        IntPtr pSacl);

    /// <summary>SetSecurityInfo on a held handle (aclapi.h).</summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint SetSecurityInfo(
        SafeFileHandle handle,
        uint objectType,
        uint securityInformation,
        IntPtr psidOwner,
        IntPtr psidGroup,
        IntPtr pDacl,
        IntPtr pSacl);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateDirectoryW(
        string lpPathName,
        ref SecurityAttributes lpSecurityAttributes);
}

/// <summary>SECURITY_ATTRIBUTES for private-ACL object creation.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SecurityAttributes
{
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    public int bInheritHandle;
}
