using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// P/Invoke surface for CreateProcessW with STARTUPINFOEX and
/// PROC_THREAD_ATTRIBUTE_JOB_LIST. This enables atomic job assignment at
/// process creation time, eliminating the race between Process.Start and
/// AssignProcessToJobObject where the child could escape on parent crash.
///
/// Verified against Microsoft docs (October 2026):
/// CreateProcessW (processthreadsapi.h / Kernel32),
/// InitializeProcThreadAttributeList (processthreadsapi.h / Kernel32),
/// UpdateProcThreadAttribute (processthreadsapi.h / Kernel32),
/// DeleteProcThreadAttributeList (processthreadsapi.h / Kernel32).
/// </summary>
public static class ProcessNative
{
    /// <summary>PROC_THREAD_ATTRIBUTE_JOB_LIST (0x0002000D).</summary>
    public const uint ProcThreadAttributeJobList = 0x0002000D;

    /// <summary>EXTENDED_STARTUPINFO_PRESENT: use STARTUPINFOEX.</summary>
    public const uint ExtendedStartupinfoPresent = 0x00080000;

    /// <summary>CREATE_NO_WINDOW: no console window for child.</summary>
    public const uint CreateNoWindow = 0x08000000;

    /// <summary>CREATE_UNICODE_ENVIRONMENT: environment is Unicode.</summary>
    public const uint CreateUnicodeEnvironment = 0x00000400;

    /// <summary>STARTF_USESTDHANDLES: use hStdInput/hStdOutput/hStdError.</summary>
    public const uint StartfUseStdHandles = 0x00000100;

    /// <summary>INFINITE timeout for attribute list size query.</summary>
    public const uint Infinite = 0xFFFFFFFF;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcessW(
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFOEXW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        uint dwAttributeCount,
        uint dwFlags,
        ref UIntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,
        uint dwFlags,
        UIntPtr attribute,
        IntPtr lpValue,
        UIntPtr cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
}

/// <summary>
/// STARTUPINFOEXW structure for CreateProcessW with extended attributes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFOEXW
{
    public STARTUPINFOEXW()
    {
        StartupInfo = new STARTUPINFOW();
        lpAttributeList = IntPtr.Zero;
    }

    public STARTUPINFOW StartupInfo;
    public IntPtr lpAttributeList;
}

/// <summary>
/// STARTUPINFOW structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFOW
{
    public STARTUPINFOW()
    {
        cb = (uint)Marshal.SizeOf<STARTUPINFOW>();
    }

    public uint cb;
    public string? lpReserved;
    public string? lpDesktop;
    public string? lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

/// <summary>
/// PROCESS_INFORMATION structure returned by CreateProcessW.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

/// <summary>
/// Safe handle for a process handle that closes via CloseHandle.
/// </summary>
public sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeProcessHandle()
        : base(ownsHandle: true)
    {
    }

    public SafeProcessHandle(IntPtr preexistingHandle)
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
/// Safe handle for a thread handle that closes via CloseHandle.
/// </summary>
public sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeThreadHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle()
    {
        return Kernel32Native.CloseHandle(handle);
    }
}