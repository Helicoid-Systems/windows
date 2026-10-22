using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// P/Invoke surface for Remote Desktop Services session queries.
/// Verified against Microsoft docs (10 October 2026):
/// WTSGetActiveConsoleSessionId (winbase.h / Kernel32),
/// WTSQuerySessionInformationW (wtsapi32.h / Wtsapi32),
/// WTSFreeMemory (wtsapi32.h / Wtsapi32),
/// ProcessIdToSessionId (processthreadsapi.h / Kernel32).
/// </summary>
public static class WtsNative
{
    /// <summary>WTS_CURRENT_SERVER_HANDLE: local RD Session Host server.</summary>
    public static readonly IntPtr CurrentServerHandle = IntPtr.Zero;

    // WTS_INFO_CLASS values used here (see wtsapi32.h enumeration order).
    public const int WtsConnectState = 8;
    public const int WtsClientProtocolType = 16;
    public const int WtsSessionInfoEx = 25;

    /// <summary>
    /// Expected byte counts for the primitive buffers this probe reads.
    /// WTS_CONNECTSTATE_CLASS is a 4-byte enum; WTSClientProtocolType is USHORT.
    /// </summary>
    public const int ConnectStateBytes = 4;
    public const int ProtocolTypeBytes = 2;

    /// <summary>Hard cap on any WTS buffer this probe accepts.</summary>
    public const int MaxQueryBufferBytes = 256;

    [DllImport("kernel32.dll")]
    public static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSQuerySessionInformationW(
        IntPtr hServer,
        uint sessionId,
        int wtsInfoClass,
        out IntPtr ppBuffer,
        out uint pBytesReturned);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);
}

/// <summary>
/// Owns a WTS-allocated buffer and always releases it with WTSFreeMemory.
/// </summary>
public sealed class SafeWtsMemory : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeWtsMemory()
        : base(ownsHandle: true)
    {
    }

    public SafeWtsMemory(IntPtr preexistingHandle)
        : base(ownsHandle: true)
    {
        SetHandle(preexistingHandle);
    }

    protected override bool ReleaseHandle()
    {
        WtsNative.WTSFreeMemory(handle);
        return true;
    }
}
