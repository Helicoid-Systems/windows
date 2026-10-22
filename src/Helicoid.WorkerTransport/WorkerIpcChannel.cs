using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform.Native;

// This file contains Windows-only named pipe IPC code.
// PipeTransmissionMode.Message is only supported on Windows.
#pragma warning disable CA1416

namespace Helicoid.WindowsPlatform;
/// <summary>
/// Worker-side authenticated named pipe client. Uses NamedPipeClientStream
/// with async operations and proper cancellation. Connects to the supervisor's
/// pipe and performs the handshake with capability nonce and process identity.
///
/// Mutual authentication: the worker verifies the supervisor's kernel PID,
/// WTS session, and token SID via GetNamedPipeServerProcessId plus
/// ProcessIdToSessionId and OpenProcessToken on that PID. A missing or
/// mismatched field denies the connection — never best-effort.
/// </summary>
public sealed class WorkerIpcChannel : IDisposable
{
    /// <summary>Upper bound on any single write so a silent peer cannot stall I/O.</summary>
    private static readonly TimeSpan MaxWriteTimeout = TimeSpan.FromSeconds(5);

    private readonly string _pipeName;
    private readonly LaunchCapability _capability;
    private readonly uint _expectedServerPid;
    private readonly uint _expectedServerSessionId;
    private readonly string _expectedServerSid;
    private readonly FencingIds _fence;
    private readonly uint _generation;
    private NamedPipeClientStream? _pipeStream;
    private readonly CancellationTokenSource _disposeCts = new();
    private bool _disposed;

    /// <summary>
    /// Create a worker-side IPC channel.
    /// </summary>
    /// <param name="pipeName">Pipe name received from the supervisor.</param>
    /// <param name="capability">Per-launch capability nonce.</param>
    /// <param name="expectedServerPid">Expected parent/supervisor PID for mutual identity check.</param>
    /// <param name="expectedServerSessionId">Expected supervisor WTS session ID.</param>
    /// <param name="expectedServerSid">Expected supervisor token user SID.</param>
    /// <param name="fence">Boot and launch fencing IDs issued for this launch.</param>
    /// <param name="generation">Desktop generation for this launch.</param>
    public WorkerIpcChannel(
        string pipeName,
        LaunchCapability capability,
        uint expectedServerPid,
        uint expectedServerSessionId,
        string expectedServerSid,
        FencingIds fence,
        uint generation)
    {
        if (string.IsNullOrEmpty(pipeName))
        {
            throw new ArgumentException("Pipe name is mandatory.", nameof(pipeName));
        }

        if (expectedServerPid == 0)
        {
            throw new ArgumentException("Expected server PID is mandatory and must be non-zero.", nameof(expectedServerPid));
        }

        if (string.IsNullOrEmpty(expectedServerSid)
            || !HandshakeRequestPayload.TryValidateTokenSid(expectedServerSid, out _))
        {
            throw new ArgumentException("Expected server token SID is mandatory and must be well-formed.", nameof(expectedServerSid));
        }

        if (fence.BootId is null || fence.BootId.Length != FencingIds.IdLength
            || fence.LaunchId is null || fence.LaunchId.Length != FencingIds.IdLength)
        {
            throw new ArgumentException("Boot and launch fencing IDs are mandatory 16-byte values.", nameof(fence));
        }

        _pipeName = pipeName;
        _capability = capability;
        _expectedServerPid = expectedServerPid;
        _expectedServerSessionId = expectedServerSessionId;
        _expectedServerSid = expectedServerSid;
        _fence = fence;
        _generation = generation;
    }

    /// <summary>
    /// Connect to the supervisor pipe and perform the handshake (async).
    /// Returns the authentication result.
    /// </summary>
    public async Task<IpcAuthenticationResult> ConnectAndHandshakeAsync(
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            // Connect to pipe with timeout.
            _pipeStream = new NamedPipeClientStream(
                ".",
                _pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _disposeCts.Token);
            connectCts.CancelAfter(timeout);

            await _pipeStream.ConnectAsync((int)timeout.TotalMilliseconds, connectCts.Token).ConfigureAwait(false);

            // Mutual kernel identity: verify server PID, session, and SID.
            if (!TryGetServerPid(out uint serverPid) || serverPid != _expectedServerPid)
            {
                return IpcAuthenticationResult.ProcessMismatch;
            }

            if (!WtsNative.ProcessIdToSessionId(serverPid, out uint serverSessionId)
                || serverSessionId != _expectedServerSessionId)
            {
                return IpcAuthenticationResult.SessionMismatch;
            }

            string? serverSid = KernelIdentity.ReadProcessTokenSid(serverPid);
            if (serverSid is null
                || !string.Equals(serverSid, _expectedServerSid, StringComparison.Ordinal))
            {
                return IpcAuthenticationResult.TokenMismatch;
            }

            // Send handshake request with our identity and capability.
            uint pid = Kernel32Native.GetCurrentProcessId();
            if (!WtsNative.ProcessIdToSessionId(pid, out uint sessionId))
            {
                return IpcAuthenticationResult.MissingIdentity;
            }

            string? sid = KernelIdentity.ReadProcessTokenSid(pid);
            if (string.IsNullOrEmpty(sid))
            {
                return IpcAuthenticationResult.MissingIdentity;
            }

            var request = new HandshakeRequestPayload
            {
                WorkerProcessId = pid,
                WorkerSessionId = sessionId,
                CapabilityNonce = _capability.Bytes,
                BootId = _fence.BootId,
                LaunchId = _fence.LaunchId,
                DesktopGeneration = _generation,
                TokenSid = sid!,
            };

            var msg = new IpcMessage
            {
                Type = IpcMessageType.HandshakeRequest,
                Payload = request.Serialize(),
            };

            if (!await TrySendMessageAsync(msg, ct).ConfigureAwait(false))
            {
                return IpcAuthenticationResult.TransportFailure;
            }

            // Read handshake response.
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _disposeCts.Token);
            readCts.CancelAfter(timeout);

            var readResult = await TryReadMessageAsync(readCts.Token).ConfigureAwait(false);
            if (readResult != IpcReadResult.Success
                || _lastReadMessage is not { Type: IpcMessageType.HandshakeResponse } respMsg)
            {
                return readResult == IpcReadResult.Malformed
                    ? IpcAuthenticationResult.MalformedFrame
                    : IpcAuthenticationResult.Timeout;
            }

            if (!HandshakeResponsePayload.TryDeserialize(respMsg.Payload, out var response))
            {
                return IpcAuthenticationResult.MissingIdentity;
            }

            // Response fence must match this launch — mandatory, never optional.
            if (!_fence.MatchesBoot(response.BootId)
                || !_fence.MatchesLaunch(response.LaunchId)
                || response.DesktopGeneration != _generation)
            {
                return IpcAuthenticationResult.FenceMismatch;
            }

            return response.Accepted
                ? IpcAuthenticationResult.Authenticated
                : (IpcAuthenticationResult)response.RejectionReason;
        }
        catch (OperationCanceledException)
        {
            return IpcAuthenticationResult.Timeout;
        }
        catch (Exception)
        {
            return IpcAuthenticationResult.TransportFailure;
        }
    }

    /// <summary>
    /// Synchronous wrapper for backward compatibility.
    /// </summary>
    public IpcAuthenticationResult ConnectAndHandshake(TimeSpan timeout)
    {
        return ConnectAndHandshakeAsync(timeout).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Send a message to the supervisor (async). Every write is bounded by
    /// <see cref="MaxWriteTimeout"/>; a silent or wedged peer cannot stall
    /// the caller.
    /// </summary>
    public async Task<bool> TrySendMessageAsync(IpcMessage message, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_pipeStream is null || !_pipeStream.IsConnected) return false;

        byte[] frame = message.Serialize();
        using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _disposeCts.Token);
        writeCts.CancelAfter(MaxWriteTimeout);
        try
        {
            await _pipeStream.WriteAsync(frame, writeCts.Token).ConfigureAwait(false);
            await _pipeStream.FlushAsync(writeCts.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
        }
    }

    /// <summary>
    /// Synchronous wrapper for TrySendMessage. Always bounded.
    /// </summary>
    public bool TrySendMessage(IpcMessage message)
    {
        return TrySendMessageAsync(message, _disposeCts.Token).GetAwaiter().GetResult();
    }

    private IpcMessage? _lastReadMessage;

    /// <summary>
    /// Read a bounded frame from the supervisor. Unknown types and malformed
    /// frames return <see cref="IpcReadResult.Malformed"/> — fail closed.
    /// </summary>
    public async Task<IpcReadResult> TryReadMessageAsync(CancellationToken ct)
    {
        _lastReadMessage = null;
        if (_pipeStream is null || !_pipeStream.IsConnected) return IpcReadResult.Disconnected;

        try
        {
            _pipeStream.ReadMode = PipeTransmissionMode.Message;

            byte[] header = new byte[IpcMessage.HeaderSize];
            int totalRead = 0;
            while (totalRead < IpcMessage.HeaderSize)
            {
                int read = await _pipeStream.ReadAsync(header.AsMemory(totalRead, IpcMessage.HeaderSize - totalRead), ct).ConfigureAwait(false);
                if (read == 0) return IpcReadResult.Disconnected;
                totalRead += read;
            }

            int payloadLen = BitConverter.ToInt32(header, 1);
            if (payloadLen < 0 || payloadLen > IpcMessage.MaxPayloadSize)
            {
                return IpcReadResult.Malformed;
            }

            byte[] frame;
            if (payloadLen == 0)
            {
                frame = header;
            }
            else
            {
                frame = new byte[IpcMessage.HeaderSize + payloadLen];
                Buffer.BlockCopy(header, 0, frame, 0, IpcMessage.HeaderSize);
                totalRead = 0;
                while (totalRead < payloadLen)
                {
                    int read = await _pipeStream.ReadAsync(frame.AsMemory(IpcMessage.HeaderSize + totalRead, payloadLen - totalRead), ct).ConfigureAwait(false);
                    if (read == 0) return IpcReadResult.Disconnected;
                    totalRead += read;
                }
            }

            try
            {
                if (IpcMessage.TryDeserialize(frame, frame.Length, out var message))
                {
                    _lastReadMessage = message;
                    return IpcReadResult.Success;
                }

                return IpcReadResult.Malformed;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(frame);
            }
        }
        catch (OperationCanceledException)
        {
            return IpcReadResult.Timeout;
        }
        catch (IOException)
        {
            return IpcReadResult.Disconnected;
        }
    }

    /// <summary>
    /// Read a message from the supervisor (sync wrapper).
    /// </summary>
    public bool TryReadMessage(TimeSpan timeout, out IpcMessage message)
        => TryReadMessage(timeout, CancellationToken.None, out message);

    /// <summary>
    /// Read a message from the supervisor (sync wrapper with cancellation).
    /// </summary>
    public bool TryReadMessage(TimeSpan timeout, CancellationToken ct, out IpcMessage message)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var result = TryReadMessageAsync(cts.Token).GetAwaiter().GetResult();
        message = _lastReadMessage ?? default;
        return result == IpcReadResult.Success;
    }

    /// <summary>
    /// Build the fence stamp for post-handshake messages on this channel.
    /// </summary>
    public FenceStamp CreateFenceStamp()
        => new()
        {
            BootId = (byte[])_fence.BootId.Clone(),
            LaunchId = (byte[])_fence.LaunchId.Clone(),
            Generation = _generation,
        };

    /// <summary>
    /// Read one message and require it to be <paramref name="expectedType"/>
    /// carrying a fence stamp that matches this channel. Unknown types and
    /// fence mismatches fail closed.
    /// </summary>
    public async Task<(IpcReadResult Result, IpcMessage Message)> ReadFencedMessageAsync(
        IpcMessageType expectedType,
        CancellationToken ct)
    {
        var result = await TryReadMessageAsync(ct).ConfigureAwait(false);
        if (result != IpcReadResult.Success || _lastReadMessage is not { } read)
        {
            return (result, default);
        }

        if (read.Type != expectedType)
        {
            _lastReadMessage = null;
            return (IpcReadResult.Malformed, default);
        }

        if (!FenceStamp.TryDeserialize(read.Payload, out var stamp) || !stamp.Matches(CreateFenceStamp()))
        {
            _lastReadMessage = null;
            return (IpcReadResult.Malformed, default);
        }

        return (IpcReadResult.Success, read);
    }

    /// <summary>
    /// Get the server process ID from the kernel pipe handle (mutual identity).
    /// Uses a non-owning wrapper so the pipe handle stays alive for the stream.
    /// </summary>
    private bool TryGetServerPid(out uint serverPid)
    {
        serverPid = 0;
        if (_pipeStream is null) return false;

        IntPtr pipeHandle = _pipeStream.SafePipeHandle?.DangerousGetHandle() ?? IntPtr.Zero;
        if (pipeHandle == IntPtr.Zero) return false;

        // Use non-owning wrapper to avoid closing the pipe handle.
        using var safeHandle = new NonOwningPipeHandle(pipeHandle);
        return PipeNative.GetNamedPipeServerProcessId(safeHandle, out serverPid);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            // Cancel in-flight I/O first so pending reads/writes unblock.
            try { _disposeCts.Cancel(); } catch (ObjectDisposedException) { }
            _pipeStream?.Dispose();
            _pipeStream = null;
            _disposeCts.Dispose();
        }
    }
}

/// <summary>
/// Kernel-backed process identity reads shared by both IPC sides.
/// </summary>
public static class KernelIdentity
{
    /// <summary>
    /// Convert an already-open token into its validated user SID.
    /// </summary>
    public static string? GetTokenUserSid(IntPtr tokenHandle)
    {
        if (!PipeNative.GetTokenInformation(tokenHandle, PipeNative.TokenUser, IntPtr.Zero, 0, out int needed) || needed <= 0)
        {
            return null;
        }

        IntPtr buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!PipeNative.GetTokenInformation(tokenHandle, PipeNative.TokenUser, buffer, needed, out _))
            {
                return null;
            }

            IntPtr pSid = Marshal.ReadIntPtr(buffer);
            if (!PipeNative.ConvertSidToStringSidW(pSid, out IntPtr pStringSid))
            {
                return null;
            }

            try
            {
                return Marshal.PtrToStringUni(pStringSid);
            }
            finally
            {
                Kernel32Native.LocalFree(pStringSid);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Read the token user SID string for a process via OpenProcess + OpenProcessToken.
    /// Returns null when the identity cannot be established — callers deny.
    /// </summary>
    public static string? ReadProcessTokenSid(uint processId)
    {
        IntPtr hProcess = Kernel32Native.OpenProcess(
            PipeNative.PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            processId);
        if (hProcess == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            if (!PipeNative.OpenProcessToken(hProcess, 0x0008 /* TOKEN_QUERY */, out var tokenHandle))
            {
                return null;
            }

            using (tokenHandle)
            {
                return GetTokenUserSid(tokenHandle.DangerousGetHandle());
            }
        }
        finally
        {
            Kernel32Native.CloseHandle(hProcess);
        }
    }
}
