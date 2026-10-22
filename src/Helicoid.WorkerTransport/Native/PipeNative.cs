using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// P/Invoke surface for named pipe creation and process/token identity checks.
/// Used by the authenticated IPC channel between supervisor and child worker.
///
/// Verified against Microsoft docs (October 2026):
/// CreateNamedPipeW (namedpipeapi.h / Kernel32),
/// ConnectNamedPipe (namedpipeapi.h / Kernel32),
/// GetNamedPipeClientProcessId (winbase.h / Kernel32),
/// OpenProcessToken (processthreadsapi.h / Advapi32),
/// GetTokenInformation (securitybaseapi.h / Advapi32),
/// GetSecurityInfo (aclapi.h / Advapi32),
/// ConvertSidToStringSidW (sddl.h / Advapi32),
/// EqualSid (securitybaseapi.h / Advapi32).
/// </summary>
public static class PipeNative
{
    // Pipe access modes.
    public const uint PipeAccessInbound = 0x00000001;
    public const uint PipeAccessOutbound = 0x00000002;
    public const uint PipeAccessDuplex = 0x00000003;

    // Pipe mode flags.
    public const uint PipeTypeByte = 0x00000000;
    public const uint PipeTypeMessage = 0x00000004;
    public const uint PipeReadModeByte = 0x00000000;
    public const uint PipeReadModeMessage = 0x00000002;
    public const uint PipeWait = 0x00000000;
    public const uint PipeNowait = 0x00000001;

    // Pipe buffer sizes.
    public const uint DefaultBufferSize = 4096;
    public const uint MaxMessageSize = 65536;

    // Pipe instances.
    public const uint PipeUnlimitedInstances = 255;

    // Timeout.
    public const uint NmpwaitUseDefaultWait = 0;
    public const uint NmpwaitForever = 0xFFFFFFFF;

    // Security attributes.
    public const uint SecurityDescriptorRevision = 1;
    public const uint OwnerSecurityInformation = 0x00000001;
    public const uint GroupSecurityInformation = 0x00000002;
    public const uint DaclSecurityInformation = 0x00000004;
    public const uint SaclSecurityInformation = 0x00000008;
    public const uint LabelSecurityInformation = 0x00000010;
    public const uint AttributeSecurityInformation = 0x00000020;
    public const uint ScopeSecurityInformation = 0x00000040;
    public const uint ProcessTrustLabelSecurityInformation = 0x00000080;
    public const uint BackupSecurityInformation = 0x00010000;
    public const uint ProtectedDaclSecurityInformation = 0x80000000;
    public const uint ProtectedSaclSecurityInformation = 0x40000000;
    public const uint UnprotectedDaclSecurityInformation = 0x20000000;
    public const uint UnprotectedSaclSecurityInformation = 0x10000000;

    // Token information classes.
    public const int TokenUser = 1;
    public const int TokenSessionId = 12;

    // SE_OBJECT_TYPE.
    public const uint SE_KERNEL_OBJECT = 6;

    // PROCESS access rights.
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // GENERIC access rights.
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint GENERIC_EXECUTE = 0x20000000;
    public const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
    public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    public const uint INVALID_HANDLE_VALUE = unchecked((uint)(-1));

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern NativeSafePipeHandle CreateNamedPipeW(
        string lpName,
        uint dwOpenMode,
        uint dwPipeMode,
        uint nMaxInstances,
        uint nOutBufferSize,
        uint nInBufferSize,
        uint nDefaultTimeout,
        IntPtr lpSecurityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConnectNamedPipe(
        NativeSafePipeHandle hNamedPipe,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DisconnectNamedPipe(NativeSafePipeHandle hNamedPipe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeClientProcessId(
        SafeHandle hNamedPipe,
        out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeServerProcessId(
        SafeHandle hNamedPipe,
        out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern NativeSafePipeHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr hProcessHandle,
        uint dwDesiredAccess,
        out SafeTokenHandle hTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(
        IntPtr hTokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetSecurityInfo(
        IntPtr hHandle,
        uint objectType,
        uint securityInformation,
        out IntPtr pSidOwner,
        out IntPtr pSidGroup,
        out IntPtr pDacl,
        out IntPtr pSacl,
        out IntPtr ppSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertSidToStringSidW(
        IntPtr pSid,
        out IntPtr stringSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsValidSid(IntPtr pSid);

    [DllImport("advapi32.dll")]
    public static extern int GetLengthSid(IntPtr pSid);

    [DllImport("kernel32.dll")]
    public static extern void LocalFree(IntPtr hMem);
}

/// <summary>
/// Safe handle for a Windows named pipe created via CreateNamedPipeW/CreateFileW.
/// Renamed to avoid ambiguity with System.IO.Pipes.SafePipeHandle.
/// </summary>
public sealed class NativeSafePipeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public NativeSafePipeHandle()
        : base(ownsHandle: true)
    {
    }

    public NativeSafePipeHandle(IntPtr preexistingHandle)
        : base(ownsHandle: true)
    {
        SetHandle(preexistingHandle);
    }

    protected override bool ReleaseHandle()
    {
        return Kernel32Native.CloseHandle(handle);
    }
}

/// <summary>
/// Non-owning safe handle wrapper for querying pipe metadata.
/// Used when we need to call pipe P/Inves on a handle owned by another
/// safe handle (e.g., SafePipeHandle from NamedPipeClientStream/ServerStream).
/// Does NOT close the underlying handle on dispose.
/// </summary>
public sealed class NonOwningPipeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public NonOwningPipeHandle(IntPtr handle)
        : base(ownsHandle: false)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        // We don't own the handle; the original safe handle does.
        return true;
    }
}

/// <summary>
/// Safe handle for a Windows token.
/// </summary>
public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeTokenHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle()
    {
        return Kernel32Native.CloseHandle(handle);
    }
}