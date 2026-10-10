using System.Diagnostics;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform;
using Helicoid.WindowsPlatform.Native;

namespace Helicoid.CaptureWorker;

/// <summary>
/// Helicoid CaptureWorker: metadata-only child worker process.
///
/// No pixels, input, or networking are enabled until a real admitted ABI exists.
/// This worker connects to the supervisor via authenticated IPC with mutual
/// kernel PID/session/SID identity, reads its per-launch capability and fencing
/// IDs from private environment variables (immediately erased), and runs a
/// bounded event loop reporting metadata status only.
///
/// Boot ID, launch ID, desktop generation, and session/user identity are
/// mandatory on both sides. Malformed or missing fields deny the connection —
/// never best-effort. Unknown or malformed operation messages fail closed.
///
/// Environment variables (set by supervisor, erased on read):
///   HELI_WORKER_CAP    — hex-encoded 32-byte capability nonce
///   HELI_WORKER_PIPE   — named pipe name for IPC
///   HELI_WORKER_GEN    — desktop generation counter (uint)
///   HELI_WORKER_BOOT   — hex-encoded 16-byte supervisor boot ID
///   HELI_WORKER_LAUNCH — hex-encoded 16-byte per-launch ID
///
/// Exit codes:
///   0 — clean shutdown
///   1 — configuration error (missing/invalid env vars)
///   2 — IPC connection failed
///   3 — authentication failed
///   4 — supervisor disconnected
///   5 — protocol violation (unknown/malformed message)
/// </summary>
internal static class Program
{
    private const int ExitClean = 0;
    private const int ExitConfigError = 1;
    private const int ExitIpcFailed = 2;
    private const int ExitAuthFailed = 3;
    private const int ExitDisconnected = 4;
    private const int ExitProtocolViolation = 5;

    private const string EnvCapability = "HELI_WORKER_CAP";
    private const string EnvPipeName = "HELI_WORKER_PIPE";
    private const string EnvGeneration = "HELI_WORKER_GEN";
    private const string EnvBootId = "HELI_WORKER_BOOT";
    private const string EnvLaunchId = "HELI_WORKER_LAUNCH";

    static int Main(string[] args)
    {
        // Read and immediately erase private environment variables.
        // Every field is mandatory: missing or malformed values deny startup.
        if (!TryReadAndEraseEnv(
            out string? capHex,
            out string? pipeName,
            out uint generation,
            out byte[]? bootId,
            out byte[]? launchId))
        {
            return ExitConfigError;
        }

        // Parse capability nonce.
        byte[] capBytes;
        try
        {
            capBytes = Convert.FromHexString(capHex!);
        }
        catch (Exception)
        {
            return ExitConfigError;
        }

        if (capBytes.Length != LaunchCapability.Length)
        {
            return ExitConfigError;
        }

        var capability = LaunchCapability.FromBytes(capBytes);
        var fence = new FencingIds { BootId = bootId!, LaunchId = launchId! };

        // Resolve our own kernel identity for the handshake (mandatory).
        uint pid = Kernel32Native.GetCurrentProcessId();
        if (!WtsNative.ProcessIdToSessionId(pid, out uint sessionId))
        {
            return ExitConfigError;
        }

        // Mutual kernel identity: verify the supervisor (parent) PID/session/SID.
        uint parentPid = GetParentProcessId();
        if (parentPid == 0)
        {
            return ExitConfigError;
        }

        if (!WtsNative.ProcessIdToSessionId(parentPid, out uint parentSessionId))
        {
            return ExitConfigError;
        }

        string? parentSid = KernelIdentity.ReadProcessTokenSid(parentPid);
        if (string.IsNullOrEmpty(parentSid))
        {
            return ExitConfigError;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var channel = new WorkerIpcChannel(
            pipeName!,
            capability,
            parentPid,
            parentSessionId,
            parentSid!,
            fence,
            generation);
        var authResult = channel.ConnectAndHandshake(TimeSpan.FromSeconds(30));

        if (authResult != IpcAuthenticationResult.Authenticated)
        {
            return ExitAuthFailed;
        }

        // Run the metadata-only event loop.
        // No pixels, input, or networking — this is a diagnostic skeleton.
        int loopResult;
        try
        {
            loopResult = RunEventLoop(channel, cts.Token);
        }
        catch (OperationCanceledException)
        {
            loopResult = ExitClean;
        }
        catch (Exception)
        {
            loopResult = ExitDisconnected;
        }

        return loopResult;
    }

    /// <summary>
    /// Read private environment variables and immediately erase them so they
    /// are not visible to child processes or diagnostic dumps.
    /// All five fields are mandatory; missing or malformed values deny.
    /// </summary>
    private static bool TryReadAndEraseEnv(
        out string? capability,
        out string? pipeName,
        out uint generation,
        out byte[]? bootId,
        out byte[]? launchId)
    {
        capability = Environment.GetEnvironmentVariable(EnvCapability);
        pipeName = Environment.GetEnvironmentVariable(EnvPipeName);
        string? genStr = Environment.GetEnvironmentVariable(EnvGeneration);
        string? bootHex = Environment.GetEnvironmentVariable(EnvBootId);
        string? launchHex = Environment.GetEnvironmentVariable(EnvLaunchId);

        // Erase immediately.
        Environment.SetEnvironmentVariable(EnvCapability, null);
        Environment.SetEnvironmentVariable(EnvPipeName, null);
        Environment.SetEnvironmentVariable(EnvGeneration, null);
        Environment.SetEnvironmentVariable(EnvBootId, null);
        Environment.SetEnvironmentVariable(EnvLaunchId, null);

        bootId = null;
        launchId = null;
        generation = 0;

        if (string.IsNullOrEmpty(capability) || string.IsNullOrEmpty(pipeName))
        {
            return false;
        }

        if (!uint.TryParse(genStr, out generation))
        {
            generation = 0;
            return false;
        }

        // Fencing IDs are mandatory — never best-effort. Missing or malformed denies.
        if (string.IsNullOrEmpty(bootHex) || string.IsNullOrEmpty(launchHex))
        {
            return false;
        }

        try
        {
            bootId = Convert.FromHexString(bootHex!);
            launchId = Convert.FromHexString(launchHex!);
        }
        catch (Exception)
        {
            bootId = null;
            launchId = null;
            return false;
        }

        if (bootId.Length != FencingIds.IdLength || launchId.Length != FencingIds.IdLength)
        {
            bootId = null;
            launchId = null;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Get the parent process ID from the kernel (for mutual identity check).
    /// Uses NtQueryInformationProcess with ProcessBasicInformation to read
    /// the InheritedFromUniqueProcessId from the PEB.
    /// </summary>
    private static uint GetParentProcessId()
    {
        try
        {
            var current = System.Diagnostics.Process.GetCurrentProcess();
            IntPtr hProcess = current.Handle;

            // PROCESS_BASIC_INFORMATION: 6 pointers (48 bytes on x64, 24 on x86).
            int pbiSize = IntPtr.Size * 6;
            IntPtr pbi = System.Runtime.InteropServices.Marshal.AllocHGlobal(pbiSize);
            try
            {
                int status = NtQueryInformationProcess(
                    hProcess,
                    0, // ProcessBasicInformation
                    pbi,
                    pbiSize,
                    out _);

                if (status != 0) return 0;

                // Layout: Reserved1, PebBaseAddress, Reserved2_0, Reserved2_1,
                //         UniqueProcessId, InheritedFromUniqueProcessId
                IntPtr parentPidPtr = IntPtr.Add(pbi, IntPtr.Size * 5);
                return (uint)System.Runtime.InteropServices.Marshal.ReadIntPtr(parentPidPtr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(pbi);
            }
        }
        catch
        {
            return 0;
        }
    }

    [System.Runtime.InteropServices.DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);

    /// <summary>
    /// Metadata-only event loop. Listens for supervisor messages (heartbeat,
    /// work assignment, shutdown) and responds. Every post-handshake message
    /// must carry a matching fence stamp. Unknown types, unknown operations,
    /// and fence mismatches fail closed. No capture, pixels, input, or
    /// networking occurs here.
    /// </summary>
    private static int RunEventLoop(
        WorkerIpcChannel channel,
        CancellationToken ct)
    {
        var heartbeatTimer = Stopwatch.StartNew();
        var heartbeatTimeout = TimeSpan.FromSeconds(60);
        var ownStamp = channel.CreateFenceStamp();

        while (!ct.IsCancellationRequested)
        {
            // Read message from supervisor with timeout.
            if (!channel.TryReadMessage(TimeSpan.FromSeconds(5), out var message))
            {
                // Timeout — check if we've exceeded heartbeat timeout.
                if (heartbeatTimer.Elapsed > heartbeatTimeout)
                {
                    // Supervisor not responding; exit cleanly.
                    return ExitDisconnected;
                }
                continue;
            }

            // Reset heartbeat timer on any message from supervisor.
            heartbeatTimer.Restart();

            switch (message.Type)
            {
                case IpcMessageType.HeartbeatPing:
                    // Heartbeat carries a bare fence stamp — must match.
                    if (!FenceStamp.TryDeserialize(message.Payload, out var pingStamp) || !pingStamp.Matches(ownStamp))
                    {
                        return ExitProtocolViolation;
                    }

                    if (!channel.TrySendMessage(new IpcMessage
                    {
                        Type = IpcMessageType.HeartbeatPong,
                        Payload = ownStamp.Serialize(),
                    }))
                    {
                        return ExitDisconnected;
                    }
                    break;

                case IpcMessageType.WorkAssignment:
                    // Metadata-only: known operations only; unknown ops and
                    // fence mismatches fail closed.
                    if (!WorkAssignmentPayload.TryDeserialize(message.Payload, out var assignment)
                        || !assignment.Fence.Matches(ownStamp))
                    {
                        return ExitProtocolViolation;
                    }

                    if (assignment.Operation != WorkOperationCode.MetadataStatusQuery)
                    {
                        return ExitProtocolViolation;
                    }

                    if (!channel.TrySendMessage(new IpcMessage
                    {
                        Type = IpcMessageType.WorkAck,
                        Payload = new WorkAckPayload
                        {
                            Fence = ownStamp,
                            Operation = assignment.Operation,
                        }.Serialize(),
                    }))
                    {
                        return ExitDisconnected;
                    }
                    break;

                case IpcMessageType.Shutdown:
                    // Shutdown carries a bare fence stamp — must match.
                    if (!FenceStamp.TryDeserialize(message.Payload, out var shutdownStamp) || !shutdownStamp.Matches(ownStamp))
                    {
                        return ExitProtocolViolation;
                    }

                    return ExitClean;

                default:
                    // Unknown message type — fail closed.
                    return ExitProtocolViolation;
            }
        }

        return ExitClean;
    }
}
