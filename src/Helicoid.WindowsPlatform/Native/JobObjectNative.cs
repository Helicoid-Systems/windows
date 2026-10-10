using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// P/Invoke surface for Windows Job Objects. Used to enforce kill-on-parent-close
/// semantics for child worker processes. When the parent dies, the OS terminates
/// all processes assigned to the job.
///
/// Verified against Microsoft docs (October 2026):
/// CreateJobObjectW (jobapi2.h / Kernel32),
/// SetInformationJobObject (jobapi2.h / Kernel32),
/// AssignProcessToJobObject (jobapi2.h / Kernel32),
/// CloseHandle (handleapi.h / Kernel32).
/// </summary>
public static class JobObjectNative
{
    /// <summary>JOBOBJECTINFOCLASS: extended limit information.</summary>
    public const int JobObjectExtendedLimitInformation = 9;

    /// <summary>JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: terminate processes when
    /// the last handle to the job object is closed.</summary>
    public const uint JobObjectLimitKillOnJobClose = 0x2000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeJobHandle CreateJobObjectW(
        IntPtr lpJobAttributes,
        string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetInformationJobObject(
        SafeJobHandle hJobObject,
        int jobObjectInfoClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo,
        uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AssignProcessToJobObject(
        SafeJobHandle hJob,
        IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsProcessInJob(
        IntPtr hProcess,
        SafeJobHandle hJob,
        [MarshalAs(UnmanagedType.Bool)] out bool result);
}

/// <summary>
/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure.
/// Only BasicLimitInformation is used; I/O counters are zeroed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
{
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    public IO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit;
    public UIntPtr JobMemoryLimit;
    public UIntPtr PeakProcessMemoryUsed;
    public UIntPtr PeakJobMemoryUsed;
}

/// <summary>
/// JOBOBJECT_BASIC_LIMIT_INFORMATION structure.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
{
    public long PerProcessUserTimeLimit;
    public long PerJobUserTimeLimit;
    public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize;
    public UIntPtr MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public UIntPtr Affinity;
    public uint PriorityClass;
    public uint SchedulingClass;
}

/// <summary>
/// IO_COUNTERS structure (unused but required for layout).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct IO_COUNTERS
{
    public ulong ReadOperationCount;
    public ulong WriteOperationCount;
    public ulong OtherOperationCount;
    public ulong ReadTransferCount;
    public ulong WriteTransferCount;
    public ulong OtherTransferCount;
}

/// <summary>
/// Safe handle wrapper for a Windows Job Object handle.
/// </summary>
public sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeJobHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle()
    {
        return Kernel32Native.CloseHandle(handle);
    }
}