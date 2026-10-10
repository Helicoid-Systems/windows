using Helicoid.Domain.PhysicalConsole;
using Xunit;

namespace Helicoid.Domain.Tests;

public class PhysicalConsoleEligibilityPolicyTests
{
    private const int Active = WtsConnectStateValues.Active;
    private const int ConsoleProtocol = WtsProtocolTypeValues.Console;

    private static ConsolePassFacts Pass(
        uint physicalConsoleSessionId = 2,
        uint processSessionId = 2,
        int connectState = Active,
        int protocolType = ConsoleProtocol,
        bool wtsQuerySucceeded = true)
        => new(
            new WtsSessionId(physicalConsoleSessionId),
            new WtsSessionId(processSessionId),
            connectState,
            protocolType,
            wtsQuerySucceeded);

    private static PhysicalConsoleObservation Observation(
        ConsolePassFacts? first = null,
        ConsolePassFacts? second = null,
        InputDesktopCategory desktopCategory = InputDesktopCategory.Default,
        bool desktopQuerySucceeded = true)
        => new(
            first ?? Pass(),
            second ?? first ?? Pass(),
            desktopCategory,
            desktopQuerySucceeded);

    private static PhysicalConsoleEligibility Evaluate(PhysicalConsoleObservation observation)
        => PhysicalConsoleEligibilityPolicy.Evaluate(observation);

    // --- Eligible baseline ---

    [Fact]
    public void StableActiveConsoleOnDefaultDesktop_IsEligible()
    {
        var result = Evaluate(Observation());

        Assert.True(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.Eligible, result.Reason);
    }

    // --- Sentinel / session 0 ---

    [Fact]
    public void NoAttachedConsoleSentinel_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(physicalConsoleSessionId: WtsSessionId.NoAttachedConsoleSentinel),
            second: Pass(physicalConsoleSessionId: WtsSessionId.NoAttachedConsoleSentinel)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.NoConsoleSessionAttached, result.Reason);
    }

    [Fact]
    public void SessionZero_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(physicalConsoleSessionId: 0, processSessionId: 0),
            second: Pass(physicalConsoleSessionId: 0, processSessionId: 0)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.SessionZero, result.Reason);
    }

    [Fact]
    public void SentinelDoesNotWrapToNegativeSessionNumber()
    {
        var id = new WtsSessionId(WtsSessionId.NoAttachedConsoleSentinel);

        Assert.True(id.IsNoAttachedConsoleSentinel);
        Assert.False(id.IsSessionZero);
        Assert.Equal(uint.MaxValue, id.Value);
    }

    // --- Wrong / current / changed IDs ---

    [Fact]
    public void ProcessSessionMismatch_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(physicalConsoleSessionId: 2, processSessionId: 3),
            second: Pass(physicalConsoleSessionId: 2, processSessionId: 3)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ProcessSessionMismatch, result.Reason);
    }

    [Fact]
    public void ConsoleSessionChangedBetweenPasses_DeniesUnstable()
    {
        var result = Evaluate(Observation(
            first: Pass(physicalConsoleSessionId: 2),
            second: Pass(physicalConsoleSessionId: 3, processSessionId: 3)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ObservationUnstable, result.Reason);
    }

    [Fact]
    public void ProcessSessionChangedBetweenPasses_DeniesUnstable()
    {
        var result = Evaluate(Observation(
            first: Pass(physicalConsoleSessionId: 2, processSessionId: 2),
            second: Pass(physicalConsoleSessionId: 2, processSessionId: 4)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ObservationUnstable, result.Reason);
    }

    [Fact]
    public void ConnectStateChangedBetweenPasses_DeniesUnstable()
    {
        var result = Evaluate(Observation(
            first: Pass(connectState: WtsConnectStateValues.Active),
            second: Pass(connectState: WtsConnectStateValues.Disconnected)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ObservationUnstable, result.Reason);
    }

    [Fact]
    public void ProtocolChangedBetweenPasses_DeniesUnstable()
    {
        var result = Evaluate(Observation(
            first: Pass(protocolType: WtsProtocolTypeValues.Console),
            second: Pass(protocolType: WtsProtocolTypeValues.Rdp)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ObservationUnstable, result.Reason);
    }

    // --- RDP / non-console protocol ---

    [Fact]
    public void RdpProtocol_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(protocolType: WtsProtocolTypeValues.Rdp),
            second: Pass(protocolType: WtsProtocolTypeValues.Rdp)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ProtocolNotConsole, result.Reason);
    }

    [Fact]
    public void LegacyProtocol_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(protocolType: WtsProtocolTypeValues.Legacy),
            second: Pass(protocolType: WtsProtocolTypeValues.Legacy)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ProtocolNotConsole, result.Reason);
    }

    [Fact]
    public void UnknownProtocol_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(protocolType: 7),
            second: Pass(protocolType: 7)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.UnknownProtocolType, result.Reason);
    }

    // --- Connect state (lock / transition / unknown) ---

    [Theory]
    [InlineData(WtsConnectStateValues.Disconnected)]
    [InlineData(WtsConnectStateValues.Connected)]
    [InlineData(WtsConnectStateValues.ConnectQuery)]
    [InlineData(WtsConnectStateValues.Shadow)]
    [InlineData(WtsConnectStateValues.Idle)]
    [InlineData(WtsConnectStateValues.Listen)]
    [InlineData(WtsConnectStateValues.Reset)]
    [InlineData(WtsConnectStateValues.Down)]
    [InlineData(WtsConnectStateValues.Init)]
    public void NonActiveConnectState_Denies(int connectState)
    {
        var result = Evaluate(Observation(
            first: Pass(connectState: connectState),
            second: Pass(connectState: connectState)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ConnectStateNotActive, result.Reason);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(10)]
    [InlineData(int.MaxValue)]
    public void UnknownConnectState_Denies(int connectState)
    {
        var result = Evaluate(Observation(
            first: Pass(connectState: connectState),
            second: Pass(connectState: connectState)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.UnknownConnectState, result.Reason);
    }

    // --- Desktop: lock / secure / missing / non-Default ---

    [Fact]
    public void WinlogonDesktop_DeniesProtected()
    {
        var result = Evaluate(Observation(desktopCategory: InputDesktopCategory.Winlogon));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.DesktopProtected, result.Reason);
    }

    [Fact]
    public void SecureDesktop_DeniesProtected()
    {
        var result = Evaluate(Observation(desktopCategory: InputDesktopCategory.Secure));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.DesktopProtected, result.Reason);
    }

    [Fact]
    public void MissingDesktop_Denies()
    {
        var result = Evaluate(Observation(desktopCategory: InputDesktopCategory.Missing));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.DesktopMissing, result.Reason);
    }

    [Fact]
    public void DesktopQueryFailed_Denies()
    {
        var result = Evaluate(Observation(
            desktopCategory: InputDesktopCategory.Missing,
            desktopQuerySucceeded: false));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.DesktopQueryFailed, result.Reason);
    }

    [Fact]
    public void ScreenSaverDesktop_DeniesNotDefault()
    {
        var result = Evaluate(Observation(desktopCategory: InputDesktopCategory.ScreenSaver));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.DesktopNotDefault, result.Reason);
    }

    [Fact]
    public void OtherDesktop_DeniesNotDefault()
    {
        var result = Evaluate(Observation(desktopCategory: InputDesktopCategory.Other));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.DesktopNotDefault, result.Reason);
    }

    [Fact]
    public void UnknownDesktopCategory_DeniesNotDefault()
    {
        var result = Evaluate(Observation(desktopCategory: InputDesktopCategory.Unknown));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.DesktopNotDefault, result.Reason);
    }

    // --- API failure ---

    [Fact]
    public void FirstPassApiFailure_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(wtsQuerySucceeded: false),
            second: Pass()));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ApiUnavailable, result.Reason);
    }

    [Fact]
    public void SecondPassApiFailure_Denies()
    {
        var result = Evaluate(Observation(
            first: Pass(),
            second: Pass(wtsQuerySucceeded: false)));

        Assert.False(result.IsEligible);
        Assert.Equal(PhysicalConsoleDenialReason.ApiUnavailable, result.Reason);
    }

    // --- Desktop classification ---

    [Theory]
    [InlineData("Default", InputDesktopCategory.Default)]
    [InlineData("default", InputDesktopCategory.Default)]
    [InlineData("Winlogon", InputDesktopCategory.Winlogon)]
    [InlineData("Secure", InputDesktopCategory.Secure)]
    [InlineData("ScreenSaver", InputDesktopCategory.ScreenSaver)]
    [InlineData("ScreenSaver-1234", InputDesktopCategory.ScreenSaver)]
    [InlineData("Dwm-9", InputDesktopCategory.Other)]
    [InlineData("", InputDesktopCategory.Missing)]
    [InlineData(null, InputDesktopCategory.Missing)]
    public void Classify_MapsDesktopNameWithoutRetainingIt(string? name, InputDesktopCategory expected)
    {
        Assert.Equal(expected, InputDesktopCategoryClassifier.Classify(name));
    }

    // --- Fail-closed ordering: first decisive denial is reported ---

    [Fact]
    public void ApiFailure_IsReportedBeforeSentinel()
    {
        var result = Evaluate(Observation(
            first: Pass(physicalConsoleSessionId: WtsSessionId.NoAttachedConsoleSentinel, wtsQuerySucceeded: false),
            second: Pass(physicalConsoleSessionId: WtsSessionId.NoAttachedConsoleSentinel, wtsQuerySucceeded: false)));

        Assert.Equal(PhysicalConsoleDenialReason.ApiUnavailable, result.Reason);
    }

    [Fact]
    public void Sentinel_IsReportedBeforeSessionZero()
    {
        // One pass sentinel, one pass session 0: sentinel is the earlier check.
        var result = Evaluate(Observation(
            first: Pass(physicalConsoleSessionId: WtsSessionId.NoAttachedConsoleSentinel),
            second: Pass(physicalConsoleSessionId: 0, processSessionId: 0)));

        Assert.Equal(PhysicalConsoleDenialReason.NoConsoleSessionAttached, result.Reason);
    }

    [Fact]
    public void Unstable_IsReportedBeforeProtocol()
    {
        var result = Evaluate(Observation(
            first: Pass(protocolType: WtsProtocolTypeValues.Rdp),
            second: Pass(protocolType: WtsProtocolTypeValues.Console)));

        Assert.Equal(PhysicalConsoleDenialReason.ObservationUnstable, result.Reason);
    }
}
