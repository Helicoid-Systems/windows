using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Helicoid.ConsoleProbe;
using Helicoid.ConsoleProbe.Native;
using Helicoid.Domain.PhysicalConsole;

const string ToolName = "Helicoid.ConsoleProbe";
const int ExitOk = 0;
const int ExitInvocationError = 2;
const int ExitNativeQueryCheckFailed = 3;

if (args.Length == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "/?"))
{
    Console.Out.WriteLine($"{ToolName}: bounded physical-console diagnostic (D26/RD03/V40 prerequisite).");
    Console.Out.WriteLine("No arguments: full physical-console diagnostic (JSON to stdout).");
    Console.Out.WriteLine("--watch: observe for 30 seconds; group consecutive identical metadata reports.");
    Console.Out.WriteLine("--native-query-check: prove the shared UOI_NAME reader against GetThreadDesktop.");
    Console.Out.WriteLine("Exit 0 on any completed diagnostic, including eligibility=false.");
    Console.Out.WriteLine("Exit 2 for invocation parse errors. Exit 3 if --native-query-check fails.");
    return ExitOk;
}

if (args.Length == 1 && args[0] == "--native-query-check")
{
    return RunNativeQueryCheck();
}

if (args.Length == 1 && args[0] == "--watch")
{
    var segments = new List<ConsoleWatchSegment>();
    var watch = Stopwatch.StartNew();
    const int SampleCount = 31;
    for (int sample = 0; sample < SampleCount; sample++)
    {
        var current = ObserveReport();
        int second = (int)watch.Elapsed.TotalSeconds;
        if (segments.Count > 0 && segments[^1].Report == current)
        {
            segments[^1] = segments[^1] with
            {
                LastSecond = second,
                Count = segments[^1].Count + 1,
            };
        }
        else
        {
            segments.Add(new ConsoleWatchSegment(second, second, 1, current));
        }
        if (sample < SampleCount - 1)
        {
            Thread.Sleep(1000);
        }
    }
    Console.Out.WriteLine(JsonSerializer.Serialize(new
    {
        tool = ToolName,
        mode = "lock-watch",
        sampleCount = SampleCount,
        elapsedSeconds = (int)watch.Elapsed.TotalSeconds,
        observations = segments,
    }, new JsonSerializerOptions { WriteIndented = true }));
    return ExitOk;
}

if (args.Length > 0)
{
    Console.Error.WriteLine($"{ToolName}: unknown arguments. Use --help.");
    return ExitInvocationError;
}

ConsoleProbeReport report = ObserveReport();

var options = new JsonSerializerOptions
{
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never,
};
Console.Out.WriteLine(JsonSerializer.Serialize(report, options));
return ExitOk;

static ConsoleProbeReport ObserveReport()
{
    try
    {
        return ConsoleProbeReport.FromResult(PhysicalConsoleObserver.Observe());
    }
    catch (Exception)
    {
        // Fixed metadata only; exception messages, stacks and paths are never emitted.
        return ConsoleProbeReport.ObservationError();
    }
}

// Query-correctness proof only: run the shared bounded UOI_NAME reader on the
// borrowed GetThreadDesktop handle. Emits a sanitized success bool — never the
// desktop name, path, or any user info. Not physical-console eligibility,
// admission, or lock-matrix evidence.
static int RunNativeQueryCheck()
{
    bool ok;
    try
    {
        uint threadId = DesktopNative.GetCurrentThreadId();
        IntPtr borrowed = DesktopNative.GetThreadDesktop(threadId);
        if (borrowed == IntPtr.Zero)
        {
            ok = false;
        }
        else
        {
            // Borrowed handle: never CloseDesktop.
            using var handle = new BorrowedDesktopHandle(borrowed);
            ok = DesktopNameReader.TryReadUoiName(handle.DangerousGetHandle(), out _);
        }
    }
    catch (Exception)
    {
        // Bounded safe text only.
        ok = false;
    }

    var payload = new NativeQueryCheckReport(
        Tool: "Helicoid.ConsoleProbe",
        Mode: "native-query-check",
        NativeQueryCheck: ok,
        Note: "Query correctness proof only. Not physical-console eligibility, admission, or lock matrix. No desktop name is emitted.");
    var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
    Console.Out.WriteLine(JsonSerializer.Serialize(payload, jsonOptions));
    return ok ? ExitOk : ExitNativeQueryCheckFailed;
}

/// <summary>
/// Machine-readable diagnostic metadata. Sanitized reason and session numeric
/// facts only — no usernames, domains, SIDs, host names, memory addresses,
/// pixels, or passwords.
/// </summary>
internal sealed record ConsoleProbeReport(
    [property: JsonPropertyName("tool")] string Tool,
    [property: JsonPropertyName("disclaimer")] string Disclaimer,
    [property: JsonPropertyName("eligible")] bool Eligible,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("facts")] ConsoleProbeFacts Facts)
{
    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion => 2;

    /// <summary>
    /// Explicit wording required for every report: diagnostic metadata only,
    /// not admitted / capture-authorized / enrolled; no desktop generation is
    /// manufactured from WTS session facts; no remote access is enabled.
    /// </summary>
    public const string RequiredDisclaimer =
        "Diagnostic metadata only. Not admitted. Not capture-authorized. Not enrolled. "
        + "No desktop generation is manufactured from these WTS session facts. "
        + "No remote access is enabled by this tool. "
        + "This is a working candidate diagnostic, not production authorization.";

    public static ConsoleProbeReport FromResult(PhysicalConsoleEligibility eligibility)
    {
        PhysicalConsoleObservation observation = eligibility.Observation;
        ConsolePassFacts facts = observation.FirstPass;

        return new ConsoleProbeReport(
            "Helicoid.ConsoleProbe",
            RequiredDisclaimer,
            eligibility.IsEligible,
            eligibility.Reason.ToString(),
            new ConsoleProbeFacts(
                facts.PhysicalConsoleSessionId.Value,
                facts.ProcessSessionId.Value,
                facts.ConnectState,
                facts.ProtocolType,
                observation.DesktopCategory.ToString(),
                observation.IsStable,
                facts.WtsQuerySucceeded,
                observation.DesktopQuerySucceeded,
                facts.LockState.ToString(),
                facts.LockQuerySucceeded));
    }

    public static ConsoleProbeReport ObservationError()
        => new(
            "Helicoid.ConsoleProbe",
            RequiredDisclaimer,
            Eligible: false,
            Reason: nameof(PhysicalConsoleDenialReason.ApiUnavailable),
            Facts: new ConsoleProbeFacts(
                PhysicalConsoleSessionId: 0,
                ProcessSessionId: 0,
                ConnectState: 0,
                ProtocolType: 0,
                DesktopCategory: InputDesktopCategory.Missing.ToString(),
                ObservationStable: false,
                WtsQuerySucceeded: false,
                DesktopQuerySucceeded: false,
                LockState: WtsSessionLockState.Unknown.ToString(),
                LockQuerySucceeded: false));
}

internal sealed record ConsoleProbeFacts(
    [property: JsonPropertyName("physicalConsoleSessionId")] uint PhysicalConsoleSessionId,
    [property: JsonPropertyName("processSessionId")] uint ProcessSessionId,
    [property: JsonPropertyName("connectState")] int ConnectState,
    [property: JsonPropertyName("protocolType")] int ProtocolType,
    [property: JsonPropertyName("desktopCategory")] string DesktopCategory,
    [property: JsonPropertyName("observationStable")] bool ObservationStable,
    [property: JsonPropertyName("wtsQuerySucceeded")] bool WtsQuerySucceeded,
    [property: JsonPropertyName("desktopQuerySucceeded")] bool DesktopQuerySucceeded,
    [property: JsonPropertyName("lockState")] string LockState,
    [property: JsonPropertyName("lockQuerySucceeded")] bool LockQuerySucceeded);

/// <summary>
/// Sanitized --native-query-check result: success bool only, no desktop name.
/// </summary>
internal sealed record NativeQueryCheckReport(
    [property: JsonPropertyName("tool")] string Tool,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("nativeQueryCheck")] bool NativeQueryCheck,
    [property: JsonPropertyName("note")] string Note);

internal sealed record ConsoleWatchSegment(
    [property: JsonPropertyName("firstSecond")] int FirstSecond,
    [property: JsonPropertyName("lastSecond")] int LastSecond,
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("report")] ConsoleProbeReport Report);
