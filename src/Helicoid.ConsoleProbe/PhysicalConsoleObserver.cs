using System.Runtime.InteropServices;
using Helicoid.ConsoleProbe.Native;
using Helicoid.Domain.PhysicalConsole;

namespace Helicoid.ConsoleProbe;

/// <summary>
/// Observes the active physical-console session twice and classifies it with
/// <see cref="PhysicalConsoleEligibilityPolicy"/>. Native queries are bounded
/// and fail closed. No usernames, domains, SIDs, host names, memory addresses,
/// pixels, or passwords leave this type.
/// </summary>
internal static class PhysicalConsoleObserver
{
    /// <summary>
    /// Take two WTS passes around one input-desktop query and evaluate.
    /// The second pass re-reads every relevant field so a change during the
    /// desktop query is refused as unstable.
    /// </summary>
    public static PhysicalConsoleEligibility Observe()
    {
        ConsolePassFacts first = ReadPass();
        InputDesktopCategory desktopCategory;
        bool desktopQuerySucceeded = TryReadInputDesktop(out desktopCategory);
        ConsolePassFacts second = ReadPass();

        var observation = new PhysicalConsoleObservation(
            first,
            second,
            desktopCategory,
            desktopQuerySucceeded);

        return PhysicalConsoleEligibilityPolicy.Evaluate(observation);
    }

    /// <summary>
    /// One WTS observation pass. Any API failure yields a pass marked
    /// unsuccessful with sentinel/zero facts rather than throwing.
    /// </summary>
    private static ConsolePassFacts ReadPass()
    {
        try
        {
            uint physicalConsole = WtsNative.WTSGetActiveConsoleSessionId();

            uint processSession = 0;
            bool processOk = WtsNative.ProcessIdToSessionId(
                (uint)Environment.ProcessId,
                out processSession);
            if (!processOk)
            {
                return FailurePass(physicalConsole);
            }

            if (!TryQueryUInt32(WtsNative.WtsConnectState, physicalConsole, WtsNative.ConnectStateBytes, out int connectState))
            {
                return FailurePass(physicalConsole, processSession);
            }

            if (!TryQueryUInt32(WtsNative.WtsClientProtocolType, physicalConsole, WtsNative.ProtocolTypeBytes, out int protocolType))
            {
                return FailurePass(physicalConsole, processSession, connectState);
            }

            return new ConsolePassFacts(
                new WtsSessionId(physicalConsole),
                new WtsSessionId(processSession),
                connectState,
                protocolType,
                WtsQuerySucceeded: true);
        }
        catch (Exception)
        {
            // Bounded safe text only: no exception message, stack, or paths.
            // Fail closed on any native/IPC failure.
            return FailurePass(WtsSessionId.NoAttachedConsoleSentinel);
        }
    }

    private static ConsolePassFacts FailurePass(
        uint physicalConsole,
        uint processSession = 0,
        int connectState = 0,
        int protocolType = 0)
        => new(
            new WtsSessionId(physicalConsole),
            new WtsSessionId(processSession),
            connectState,
            protocolType,
            WtsQuerySucceeded: false);

    /// <summary>
    /// Query a primitive WTS field into an int. Accepts only the exact
    /// documented buffer size and always frees a nonzero WTS buffer even when
    /// the API reports failure.
    /// </summary>
    private static bool TryQueryUInt32(
        int infoClass,
        uint sessionId,
        int expectedBytes,
        out int value)
    {
        value = 0;

        if (sessionId == WtsSessionId.NoAttachedConsoleSentinel
            || expectedBytes is not (WtsNative.ConnectStateBytes or WtsNative.ProtocolTypeBytes))
        {
            return false;
        }

        bool ok = WtsNative.WTSQuerySessionInformationW(
            WtsNative.CurrentServerHandle,
            sessionId,
            infoClass,
            out IntPtr buffer,
            out uint bytesReturned);

        // Free any nonzero buffer even when the API returns false.
        if (buffer != IntPtr.Zero)
        {
            using var owned = new SafeWtsMemory(buffer);

            if (!ok)
            {
                return false;
            }

            // Primitive lengths are exact: 4 for WTS_CONNECTSTATE_CLASS, 2 for USHORT.
            if (bytesReturned != expectedBytes)
            {
                return false;
            }

            value = expectedBytes switch
            {
                WtsNative.ProtocolTypeBytes => (ushort)Marshal.ReadInt16(buffer),
                WtsNative.ConnectStateBytes => Marshal.ReadInt32(buffer),
                _ => 0,
            };

            return expectedBytes is WtsNative.ConnectStateBytes or WtsNative.ProtocolTypeBytes;
        }

        return false;
    }

    /// <summary>
    /// Observe only the current process input desktop (OpenInputDesktop with
    /// READOBJECTS + UOI_NAME via the shared bounded reader). The handle is
    /// closed in a finally-equivalent dispose. The raw name is classified and
    /// discarded; it is never emitted.
    /// </summary>
    private static bool TryReadInputDesktop(out InputDesktopCategory category)
    {
        category = InputDesktopCategory.Missing;

        try
        {
            IntPtr raw = DesktopNative.OpenInputDesktop(
                0,
                fInherit: false,
                DesktopNative.DesktopReadObjects);

            if (raw == IntPtr.Zero)
            {
                return false;
            }

            using var desktop = new SafeDesktopHandle(raw);

            if (!DesktopNameReader.TryReadUoiName(desktop.DangerousGetHandle(), out string? name))
            {
                return false;
            }

            category = InputDesktopCategoryClassifier.Classify(name);
            return true;
        }
        catch (Exception)
        {
            // Bounded safe text only: no exception message, stack, or paths.
            category = InputDesktopCategory.Missing;
            return false;
        }
    }
}
