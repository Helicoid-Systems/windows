using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// P/Invoke surface for desktop observation and query correctness checks.
/// Verified against Microsoft docs (10 October 2026):
/// OpenInputDesktop (winuser.h / User32),
/// GetThreadDesktop (winuser.h / User32) — borrowed handle, never CloseDesktop,
/// GetUserObjectInformationW (winuser.h / User32),
/// CloseDesktop (winuser.h / User32),
/// GetCurrentThreadId (processthreadsapi.h / Kernel32).
/// This probe never calls SetThreadDesktop and never impersonates.
/// </summary>
public static class DesktopNative
{
    /// <summary>DESKTOP_READOBJECTS: required for GetUserObjectInformation.</summary>
    public const uint DesktopReadObjects = 0x0001;

    /// <summary>UOI_NAME: object name string.</summary>
    public const int UoiName = 2;

    /// <summary>ERROR_INSUFFICIENT_BUFFER: expected first-call probe result.</summary>
    public const int ErrorInsufficientBuffer = 122;

    /// <summary>
    /// Bounded name capacity in UTF-16 code units (excluding terminator).
    /// </summary>
    public const int MaxDesktopNameChars = 128;

    /// <summary>
    /// Maximum accepted UOI_NAME buffer including the null terminator.
    /// </summary>
    public const int MaxNameBytes = (MaxDesktopNameChars + 1) * 2;

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenInputDesktop(
        uint dwFlags,
        [MarshalAs(UnmanagedType.Bool)] bool fInherit,
        uint dwDesiredAccess);

    /// <summary>
    /// Borrowed desktop handle for a thread. Docs: "You do not need to call
    /// CloseDesktop" — never close this handle.
    /// </summary>
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetThreadDesktop(uint dwThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetUserObjectInformationW(
        IntPtr hObj,
        int nIndex,
        byte[]? pvInfo,
        int nLength,
        out int lpnLengthNeeded);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseDesktop(IntPtr hDesktop);
}

/// <summary>
/// Owns an HDESK and always closes it with CloseDesktop.
/// Use only for handles this process opened (OpenInputDesktop).
/// </summary>
public sealed class SafeDesktopHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeDesktopHandle()
        : base(ownsHandle: true)
    {
    }

    public SafeDesktopHandle(IntPtr preexistingHandle)
        : base(ownsHandle: true)
    {
        SetHandle(preexistingHandle);
    }

    protected override bool ReleaseHandle()
    {
        return DesktopNative.CloseDesktop(handle);
    }
}

/// <summary>
/// Borrowed HDESK (GetThreadDesktop). ReleaseHandle is a no-op: the docs
/// forbid CloseDesktop on this handle.
/// </summary>
public sealed class BorrowedDesktopHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public BorrowedDesktopHandle(IntPtr preexistingHandle)
        : base(ownsHandle: true)
    {
        SetHandle(preexistingHandle);
    }

    protected override bool ReleaseHandle()
    {
        return true;
    }
}
