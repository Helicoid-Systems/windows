using Helicoid.ConsoleProbe.Native;
using Helicoid.Domain.PhysicalConsole;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Tests the exact linked WTSINFOEXW numeric-header decoder used by the
/// ConsoleProbe native query seam.
/// </summary>
public sealed class WtsInfoExDecoderTests
{
    private const uint ExpectedSession = 2;
    private const int ExpectedState = WtsConnectStateValues.Active;

    /// <summary>
    /// Build a minimal valid WTSINFOEXW numeric header buffer.
    /// Caller overwrites individual fields for negative cases.
    /// </summary>
    private static byte[] BuildHeader(
        int level = WtsInfoExDecoder.AcceptedLevel,
        uint sessionId = ExpectedSession,
        int sessionState = ExpectedState,
        int sessionFlags = WtsSessionStateFlagValues.Unlock,
        int totalBytes = WtsInfoExDecoder.MinHeaderBytes)
    {
        byte[] buf = new byte[totalBytes];
        BitConverter.GetBytes(level).CopyTo(buf, WtsInfoExDecoder.LevelOffset);
        BitConverter.GetBytes(sessionId).CopyTo(buf, WtsInfoExDecoder.SessionIdOffset);
        BitConverter.GetBytes(sessionState).CopyTo(buf, WtsInfoExDecoder.SessionStateOffset);
        BitConverter.GetBytes(sessionFlags).CopyTo(buf, WtsInfoExDecoder.SessionFlagsOffset);
        return buf;
    }

    // --- Happy paths ---

    [Fact]
    public void ValidUnlockedHeader_DecodesUnlocked()
    {
        byte[] buf = BuildHeader(sessionFlags: WtsSessionStateFlagValues.Unlock);

        Assert.True(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Unlocked, lockState);
    }

    [Fact]
    public void ValidLockedHeader_DecodesLocked()
    {
        byte[] buf = BuildHeader(sessionFlags: WtsSessionStateFlagValues.Lock);

        Assert.True(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Locked, lockState);
    }

    [Fact]
    public void ValidUnknownFlagHeader_DecodesUnknown()
    {
        byte[] buf = BuildHeader(sessionFlags: WtsSessionStateFlagValues.Unknown);

        Assert.True(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Unknown, lockState);
    }

    [Fact]
    public void NumericHeaderWithVerifiedNativeSize_Decodes()
    {
        byte[] buf = BuildHeader();

        Assert.True(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Unlocked, lockState);
    }

    // --- Truncation ---

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(12)]
    [InlineData(19)]
    public void TruncatedBuffer_IsRejected(int bytesReturned)
    {
        byte[] buf = new byte[Math.Max(bytesReturned, 1)];

        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Unknown, lockState);
    }

    [Fact]
    public void NullBuffer_IsRejected()
    {
        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            null, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Unknown, lockState);
    }

    [Fact]
    public void ShortNumericHeader_IsRejected()
    {
        byte[] buf = new byte[19];

        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out _));
    }

    [Fact]
    public void OversizedNumericHeader_IsRejected()
    {
        byte[] buf = BuildHeader(totalBytes: WtsInfoExDecoder.MinHeaderBytes + 1);

        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out _));
    }

    // --- Wrong level ---

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void WrongLevel_IsRejected(int level)
    {
        byte[] buf = BuildHeader(level: level);

        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Unknown, lockState);
    }

    // --- Mismatched session / state ---

    [Fact]
    public void MismatchedSessionId_IsRejected()
    {
        byte[] buf = BuildHeader(sessionId: ExpectedSession + 1);

        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out _));
    }

    [Theory]
    [InlineData(WtsConnectStateValues.Disconnected)]
    [InlineData(WtsConnectStateValues.Active + 1)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void MismatchedSessionState_IsRejected(int sessionState)
    {
        byte[] buf = BuildHeader(sessionState: sessionState);

        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out _));
    }

    // --- Unknown / unrecognized flag values ---

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(-2)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void UnrecognizedSessionFlags_IsRejected(int sessionFlags)
    {
        byte[] buf = BuildHeader(sessionFlags: sessionFlags);

        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            buf, WtsInfoExDecoder.StructBytes, ExpectedSession, ExpectedState, out var lockState));
        Assert.Equal(WtsSessionLockState.Unknown, lockState);
    }


    [Theory]
    [InlineData(20)]
    [InlineData(231)]
    [InlineData(233)]
    [InlineData(512)]
    public void WrongNativeStructureSize_IsRejected(int nativeBytes)
    {
        byte[] header = BuildHeader();
        Assert.False(WtsInfoExDecoder.TryDecodeSessionLock(
            header, nativeBytes, ExpectedSession, ExpectedState, out var state));
        Assert.Equal(WtsSessionLockState.Unknown, state);
    }

    // --- Layout sanity ---

    [Fact]
    public void HeaderOffsets_MatchDocumentedWtsInfoExLayout()
    {
        // Level DWORD @0, Data union aligned 8, SessionId @8, SessionState @12,
        // SessionFlags @16. Documented against WTSINFOEXW / WTSINFOEX_LEVEL1_W.
        Assert.Equal(0, WtsInfoExDecoder.LevelOffset);
        Assert.Equal(8, WtsInfoExDecoder.SessionIdOffset);
        Assert.Equal(12, WtsInfoExDecoder.SessionStateOffset);
        Assert.Equal(16, WtsInfoExDecoder.SessionFlagsOffset);
        Assert.Equal(20, WtsInfoExDecoder.MinHeaderBytes);
    }

    [Fact]
    public void StructBytes_Is232()
    {
        // Native CI 38058328331 compiled static_assert against the installed SDK.
        Assert.Equal(232, WtsInfoExDecoder.StructBytes);
    }
}
