using System.Runtime.InteropServices;

namespace Helicoid.WindowsPlatform.Native;

/// <summary>
/// Shared bounded UOI_NAME reader. Handles the documented first-call
/// FALSE/ERROR_INSUFFICIENT_BUFFER probe (learn.microsoft.com GetUserObjectInformationW),
/// allocates exactly the reported length within the cap, validates terminated
/// UTF-16, and never closes the caller's desktop handle.
/// </summary>
public static class DesktopNameReader
{
    /// <summary>
    /// Read UOI_NAME from a desktop handle.
    /// Returns false on any query or validation failure. On success,
    /// <paramref name="name"/> is the validated name string (already truncated
    /// at the terminator). The name is for classification only — callers must
    /// not emit it.
    /// </summary>
    public static bool TryReadUoiName(IntPtr desktopHandle, out string? name)
    {
        name = null;
        if (desktopHandle == IntPtr.Zero)
        {
            return false;
        }

        // Probe: nLength=0. Documented behavior is FALSE + ERROR_INSUFFICIENT_BUFFER
        // with lpnLengthNeeded set to the required byte count.
        bool probeOk = DesktopNative.GetUserObjectInformationW(
            desktopHandle,
            DesktopNative.UoiName,
            pvInfo: null,
            nLength: 0,
            out int needed);

        // Length must be positive, even (UTF-16), and within the bounded cap
        // (MaxDesktopNameChars + terminator). Never truncate a longer name.
        if (needed <= 0
            || (needed & 1) != 0
            || needed > DesktopNative.MaxNameBytes)
        {
            return false;
        }

        if (!probeOk)
        {
            int err = Marshal.GetLastWin32Error();
            if (err != DesktopNative.ErrorInsufficientBuffer)
            {
                return false;
            }
        }

        // Allocate EXACTLY the reported length — no truncation.
        byte[] buffer = new byte[needed];

        bool readOk = DesktopNative.GetUserObjectInformationW(
            desktopHandle,
            DesktopNative.UoiName,
            buffer,
            needed,
            out int written);

        if (!readOk
            || written <= 0
            || (written & 1) != 0
            || written > needed)
        {
            return false;
        }

        return TryDecodeBoundedUtf16(buffer, written, out name);
    }

    /// <summary>
    /// Decode a UOI_NAME buffer as a bounded, terminated UTF-16 string.
    /// Rejects missing terminator, embedded nulls, and unpaired surrogates.
    /// </summary>
    public static bool TryDecodeBoundedUtf16(byte[] buffer, int written, out string? name)
    {
        name = null;
        if (written <= 0 || written > buffer.Length || written > DesktopNative.MaxNameBytes || (written & 1) != 0)
        {
            return false;
        }
        int charCount = written / 2;
        if (charCount <= 0)
        {
            return false;
        }

        // Locate the first null terminator.
        int termIndex = -1;
        for (int i = 0; i < charCount; i++)
        {
            char c = (char)BitConverter.ToUInt16(buffer, i * 2);
            if (c == '\0')
            {
                termIndex = i;
                break;
            }
        }

        // Require exactly one terminator at the end of the returned name.
        // A prefix such as Default\0Winlogon\0 must never classify as Default.
        if (termIndex != charCount - 1 || termIndex == 0)
        {
            return false;
        }

        // Validate name[0..termIndex): no embedded null (guaranteed by first-null
        // scan), no unpaired UTF-16 surrogates.
        for (int i = 0; i < termIndex; i++)
        {
            char c = (char)BitConverter.ToUInt16(buffer, i * 2);

            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= termIndex)
                {
                    return false;
                }

                char low = (char)BitConverter.ToUInt16(buffer, (i + 1) * 2);
                if (!char.IsLowSurrogate(low))
                {
                    return false;
                }

                i++;
            }
            else if (char.IsLowSurrogate(c))
            {
                return false;
            }
        }

        name = new string(
            Enumerable.Range(0, termIndex)
                .Select(i => (char)BitConverter.ToUInt16(buffer, i * 2))
                .ToArray());

        return true;
    }
}
