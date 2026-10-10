using Helicoid.Domain.PhysicalConsole;

namespace Helicoid.ConsoleProbe.Native;

/// <summary>
/// Portable numeric-header decoder for WTSINFOEXW as returned by
/// WTSQuerySessionInformationW(WTSSessionInfoEx). Reads only the fixed-size
/// numeric fields; never touches WinStationName / UserName / DomainName.
///
/// Layout checked against the installed Windows SDK in native CI 38058328331,
/// 2026-10-10: WTSINFOEXW size 232, Data offset 8, SessionFlags offset 16.
/// Only the first 20 numeric bytes are copied into managed memory; trailing
/// station/user/domain strings are never copied or decoded.
/// </summary>
internal static class WtsInfoExDecoder
{
    // Numeric header offsets within WTSINFOEXW.
    public const int LevelOffset = 0;
    public const int SessionIdOffset = 8;
    public const int SessionStateOffset = 12;
    public const int SessionFlagsOffset = 16;

    /// <summary>Only WTSINFOEX_LEVEL1 is accepted.</summary>
    public const int AcceptedLevel = 1;

    /// <summary>Bytes needed to read through SessionFlags (LONG @16).</summary>
    public const int MinHeaderBytes = SessionFlagsOffset + 4;

    /// <summary>SDK-verified sizeof(WTSINFOEXW) on Windows x64.</summary>
    public const int StructBytes = 232;

    /// <summary>
    /// Decode the copied 20-byte numeric header and classify SessionFlags.
    /// bytesReturned describes the original API structure, not this header copy.
    /// Returns false on truncation, wrong level, mismatched session or state,
    /// or an unrecognized SessionFlags value. On failure
    /// <paramref name="lockState"/> is always <see cref="WtsSessionLockState.Unknown"/>.
    /// </summary>
    public static bool TryDecodeSessionLock(
        byte[]? buffer,
        int bytesReturned,
        uint expectedSessionId,
        int expectedConnectState,
        out WtsSessionLockState lockState)
    {
        lockState = WtsSessionLockState.Unknown;

        if (buffer is null
            || bytesReturned != StructBytes
            || buffer.Length != MinHeaderBytes)
        {
            return false;
        }

        int level = BitConverter.ToInt32(buffer, LevelOffset);
        if (level != AcceptedLevel)
        {
            return false;
        }

        uint sessionId = BitConverter.ToUInt32(buffer, SessionIdOffset);
        if (sessionId != expectedSessionId)
        {
            return false;
        }

        int sessionState = BitConverter.ToInt32(buffer, SessionStateOffset);
        if (sessionState != expectedConnectState)
        {
            return false;
        }

        int sessionFlags = BitConverter.ToInt32(buffer, SessionFlagsOffset);
        switch (sessionFlags)
        {
            case WtsSessionStateFlagValues.Unlock:
                lockState = WtsSessionLockState.Unlocked;
                return true;

            case WtsSessionStateFlagValues.Lock:
                lockState = WtsSessionLockState.Locked;
                return true;

            case WtsSessionStateFlagValues.Unknown:
                lockState = WtsSessionLockState.Unknown;
                return true;

            default:
                return false;
        }
    }
}
