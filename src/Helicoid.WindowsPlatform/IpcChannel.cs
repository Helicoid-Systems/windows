using System.IO.Pipes;
using System.Runtime.InteropServices;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform.Native;

// This file contains Windows-only named pipe IPC code.
// PipeTransmissionMode.Message is only supported on Windows.
#pragma warning disable CA1416

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Authentication result for IPC handshake verification.
/// </summary>
public enum IpcAuthenticationResult
{
    /// <summary>Peer identity fully verified.</summary>
    Authenticated = 0,

    /// <summary>Capability nonce mismatch.</summary>
    InvalidCapability = 1,

    /// <summary>Process ID does not match expected peer.</summary>
    ProcessMismatch = 2,

    /// <summary>WTS session ID does not match expected peer.</summary>
    SessionMismatch = 3,

    /// <summary>Token user SID does not match expected peer.</summary>
    TokenMismatch = 4,

    /// <summary>Pipe connection or read/write failure.</summary>
    TransportFailure = 5,

    /// <summary>Received an oversized or malformed frame.</summary>
    MalformedFrame = 6,

    /// <summary>Handshake timed out or canceled.</summary>
    Timeout = 7,

    /// <summary>Boot, launch, or desktop generation fence did not match.</summary>
    FenceMismatch = 8,

    /// <summary>A mandatory identity field was missing or malformed.</summary>
    MissingIdentity = 9,
}

/// <summary>
/// Outcome of a bounded frame read. Unknown/malformed frames fail closed:
/// callers must treat <see cref="Malformed"/> and <see cref="Disconnected"/>
/// as terminal, never as "keep going".
/// </summary>
public enum IpcReadResult
{
    /// <summary>A well-formed frame was read.</summary>
    Success = 0,

    /// <summary>No frame arrived within the timeout.</summary>
    Timeout = 1,

    /// <summary>The peer disconnected.</summary>
    Disconnected = 2,

    /// <summary>The frame was malformed, oversized, or an unknown type.</summary>
    Malformed = 3,
}

/// <summary>
/// Supervisor-side authenticated named pipe server. Uses
/// NamedPipeServerStream with CurrentUserOnly for restrictive ACL (same-user
/// only, no remote clients). Authenticates the connecting worker by verifying
/// the capability nonce, process ID (from kernel GetNamedPipeClientProcessId),
/// WTS session (from kernel ProcessIdToSessionId), and token user SID (from
/// OpenProcessToken on the actual child process handle).
///
/// Mutual identity: the worker independently verifies this server's kernel
/// PID, session, and SID on the same pipe handle.
///
/// The pipe name is derived from a cryptographic nonce and never exposed in
/// argv, environment variables, or public logs. The capability nonce is passed
/// to the child via private environment variables that are erased on read.
/// </summary>
public sealed class SupervisorIpcChannel : IDisposable
{
    private readonly string _pipeName;
    private readonly LaunchCapability _capability;
    private readonly FencingIds _fence;
    private readonly uint _expectedGeneration;
    private uint _expectedChildPid;
    private readonly uint _expectedChildSessionId;
    private readonly string _expectedChildSid;
    private NamedPipeServerStream? _pipeStream;
    private bool _disposed;

    /// <summary>
    /// Create a new supervisor-side IPC channel.
    /// </summary>
    /// <param name="capability">Per-launch capability nonce shared with the child.</param>
    /// <param name="expectedChildPid">Expected child process ID (0 if not yet known).</param>
    /// <param name="expectedChildSessionId">Expected child WTS session ID.</param>
    /// <param name="expectedChildSid">Expected child token user SID string.</param>
    /// <param name="fence">Boot and launch fencing IDs for this supervisor/launch.</param>
    /// <param name="expectedGeneration">Desktop generation for this launch.</param>
    public SupervisorIpcChannel(
        LaunchCapability capability,
        uint expectedChildPid,
        uint expectedChildSessionId,
        string expectedChildSid,
        FencingIds fence,
        uint expectedGeneration)
    {
        if (string.IsNullOrEmpty(expectedChildSid)
            || !HandshakeRequestPayload.TryValidateTokenSid(expectedChildSid, out _))
        {
            throw new ArgumentException("Expected child token SID is mandatory and must be well-formed.", nameof(expectedChildSid));
        }

        if (fence.BootId is null || fence.BootId.Length != FencingIds.IdLength
            || fence.LaunchId is null || fence.LaunchId.Length != FencingIds.IdLength)
        {
            throw new ArgumentException("Boot and launch fencing IDs are mandatory 16-byte values.", nameof(fence));
        }

        _capability = capability;
        _expectedChildPid = expectedChildPid;
        _expectedChildSessionId = expectedChildSessionId;
        _expectedChildSid = expectedChildSid;
        _fence = fence;
        _expectedGeneration = expectedGeneration;

        // Derive pipe name from capability nonce (first 8 bytes as hex).
        string nonceHex = Convert.ToHexString(capability.Bytes.AsSpan(0, 8));
        _pipeName = $"helicoid-worker-{nonceHex}";
    }

    /// <summary>
    /// The pipe name to pass to the child worker (via private env var).
    /// </summary>
    public string PipeName => _pipeName;

    /// <summary>
    /// Bind the expected child PID after the child has been launched.
    /// Must be called BEFORE WaitForAuthenticatedConnection. The pipe server
    /// instance stays the same — no new pipe is created, no orphaned handle.
    /// </summary>
    public void BindExpectedPid(uint childPid)
    {
        if (childPid == 0)
        {
            throw new ArgumentException("Expected child PID is mandatory and must be non-zero.", nameof(childPid));
        }

        if (_pipeStream is not null)
        {
            throw new InvalidOperationException("Cannot bind PID after pipe has started listening.");
        }

        _expectedChildPid = childPid;
    }

    /// <summary>
    /// Create the named pipe and wait for a single authenticated connection.
    /// Uses NamedPipeServerStream with CurrentUserOnly for restrictive ACL.
    /// Returns the authenticated result.
    /// </summary>
    public async Task<IpcAuthenticationResult> WaitForAuthenticatedConnectionAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            // Single-instance message pipe. .NET creates the server with a
            // current-user-only ACL by default; remote clients are rejected.
            _pipeStream = new NamedPipeServerStream(
                _pipeName,
                PipeDirection.InOut,
                1, // Single instance.
                PipeTransmissionMode.Message,
                PipeOptions.Asynchronous);

            // Wait for connection with timeout.
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(timeout);

            await _pipeStream.WaitForConnectionAsync(connectCts.Token).ConfigureAwait(false);

            // Verify client process ID from kernel (not from payload).
            uint clientPid = GetClientProcessId();
            if (clientPid == 0)
            {
                return IpcAuthenticationResult.TransportFailure;
            }

            if (_expectedChildPid == 0 || clientPid != _expectedChildPid)
            {
                return IpcAuthenticationResult.ProcessMismatch;
            }

            // Verify client session ID from kernel ProcessIdToSessionId.
            if (!WtsNative.ProcessIdToSessionId(clientPid, out uint clientSessionId))
            {
                return IpcAuthenticationResult.TransportFailure;
            }

            if (clientSessionId != _expectedChildSessionId)
            {
                return IpcAuthenticationResult.SessionMismatch;
            }

            // Verify client token SID from kernel OpenProcessToken.
            if (!TryVerifyProcessTokenSid(clientPid))
            {
                return IpcAuthenticationResult.TokenMismatch;
            }

            // Read handshake request from worker.
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readCts.CancelAfter(timeout);

            var readResult = await TryReadMessageAsync(readCts.Token).ConfigureAwait(false);
            if (readResult != IpcReadResult.Success
                || _lastReadMessage is not { Type: IpcMessageType.HandshakeRequest } reqMsg)
            {
                return readResult == IpcReadResult.Malformed
                    ? IpcAuthenticationResult.MalformedFrame
                    : IpcAuthenticationResult.Timeout;
            }

            // Deserialize and verify handshake. Missing/malformed fields deny.
            if (!HandshakeRequestPayload.TryDeserialize(reqMsg.Payload, out var request))
            {
                await SendHandshakeResponseAsync(false, HandshakeResponsePayload.ReasonMissingIdentity).ConfigureAwait(false);
                return IpcAuthenticationResult.MissingIdentity;
            }

            // Verify capability nonce (constant-time comparison).
            var expectedCap = _capability;
            var receivedCap = LaunchCapability.FromBytes(request.CapabilityNonce);
            if (!expectedCap.Matches(receivedCap))
            {
                await SendHandshakeResponseAsync(false, HandshakeResponsePayload.ReasonInvalidCapability).ConfigureAwait(false);
                return IpcAuthenticationResult.InvalidCapability;
            }

            // Verify worker-reported PID matches kernel PID.
            if (request.WorkerProcessId != clientPid)
            {
                await SendHandshakeResponseAsync(false, HandshakeResponsePayload.ReasonProcessMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.ProcessMismatch;
            }

            // Verify worker-reported session matches kernel session.
            if (request.WorkerSessionId != clientSessionId)
            {
                await SendHandshakeResponseAsync(false, HandshakeResponsePayload.ReasonSessionMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.SessionMismatch;
            }

            // Verify worker-reported SID matches kernel SID (mandatory).
            if (string.IsNullOrEmpty(request.TokenSid)
                || !string.Equals(request.TokenSid, _expectedChildSid, StringComparison.Ordinal))
            {
                await SendHandshakeResponseAsync(false, HandshakeResponsePayload.ReasonTokenMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.TokenMismatch;
            }

            // Verify mandatory fencing fields: boot, launch, generation.
            if (!_fence.MatchesBoot(request.BootId) || !_fence.MatchesLaunch(request.LaunchId))
            {
                await SendHandshakeResponseAsync(false, HandshakeResponsePayload.ReasonFenceMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.FenceMismatch;
            }

            if (request.DesktopGeneration != _expectedGeneration)
            {
                await SendHandshakeResponseAsync(false, HandshakeResponsePayload.ReasonFenceMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.FenceMismatch;
            }

            // All checks passed — authentication successful.
            await SendHandshakeResponseAsync(true, HandshakeResponsePayload.ReasonNone).ConfigureAwait(false);
            return IpcAuthenticationResult.Authenticated;
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
    public IpcAuthenticationResult WaitForAuthenticatedConnection(
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        return WaitForAuthenticatedConnectionAsync(timeout, cancellationToken)
            .GetAwaiter().GetResult();
    }

    /// <summary>
    /// Send a message to the connected worker.
    /// </summary>
    public async Task<bool> TrySendMessageAsync(IpcMessage message, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_pipeStream is null || !_pipeStream.IsConnected) return false;

        byte[] frame = message.Serialize();
        await _pipeStream.WriteAsync(frame, ct).ConfigureAwait(false);
        await _pipeStream.FlushAsync(ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Synchronous wrapper for TrySendMessage.
    /// </summary>
    public bool TrySendMessage(IpcMessage message, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        return TrySendMessageAsync(message, cts.Token).GetAwaiter().GetResult();
    }

    private IpcMessage? _lastReadMessage;

    /// <summary>
    /// Read a bounded frame from the connected worker. Unknown types and
    /// malformed frames return <see cref="IpcReadResult.Malformed"/> — callers
    /// must fail closed.
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

            if (IpcMessage.TryDeserialize(frame, frame.Length, out var message))
            {
                _lastReadMessage = message;
                return IpcReadResult.Success;
            }

            return IpcReadResult.Malformed;
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
    /// Read a message from the connected worker (sync wrapper).
    /// </summary>
    public bool TryReadMessage(TimeSpan timeout, CancellationToken cancellationToken, out IpcMessage message)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
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
            Generation = _expectedGeneration,
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

    private async Task SendHandshakeResponseAsync(bool accepted, byte reason)
    {
        var response = new HandshakeResponsePayload
        {
            Accepted = accepted,
            RejectionReason = reason,
            BootId = _fence.BootId,
            LaunchId = _fence.LaunchId,
            DesktopGeneration = _expectedGeneration,
        };

        var msg = new IpcMessage
        {
            Type = IpcMessageType.HandshakeResponse,
            Payload = response.Serialize(),
        };

        await TrySendMessageAsync(msg).ConfigureAwait(false);
    }

    /// <summary>
    /// Get the client process ID from the kernel (not from payload).
    /// Uses a non-owning wrapper so the pipe handle stays alive for the stream.
    /// </summary>
    private uint GetClientProcessId()
    {
        if (_pipeStream is null) return 0;

        IntPtr pipeHandle = _pipeStream.SafePipeHandle?.DangerousGetHandle() ?? IntPtr.Zero;
        if (pipeHandle == IntPtr.Zero) return 0;

        // Use non-owning wrapper to avoid closing the pipe handle.
        using var safeHandle = new NonOwningPipeHandle(pipeHandle);
        if (PipeNative.GetNamedPipeClientProcessId(safeHandle, out uint clientPid))
        {
            return clientPid;
        }

        return 0;
    }

    /// <summary>
    /// Verify the process token SID from the kernel (not from payload).
    /// Opens the process by PID, gets its token, and compares the SID.
    /// </summary>
    private bool TryVerifyProcessTokenSid(uint processId)
    {
        string? sid = KernelIdentity.ReadProcessTokenSid(processId);
        return sid is not null && string.Equals(sid, _expectedChildSid, StringComparison.Ordinal);
    }

    /// <summary>
    /// Disconnect the pipe.
    /// </summary>
    public void Disconnect()
    {
        try
        {
            if (_pipeStream is not null && _pipeStream.IsConnected)
            {
                _pipeStream.Disconnect();
            }
        }
        catch (Exception)
        {
            // Disconnect must not throw.
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            Disconnect();
            _pipeStream?.Dispose();
            _pipeStream = null;
        }
    }
}

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
    private readonly string _pipeName;
    private readonly LaunchCapability _capability;
    private readonly uint _expectedServerPid;
    private readonly uint _expectedServerSessionId;
    private readonly string _expectedServerSid;
    private readonly FencingIds _fence;
    private readonly uint _generation;
    private NamedPipeClientStream? _pipeStream;
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

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
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
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
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
    /// Send a message to the supervisor (async).
    /// </summary>
    public async Task<bool> TrySendMessageAsync(IpcMessage message, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_pipeStream is null || !_pipeStream.IsConnected) return false;

        byte[] frame = message.Serialize();
        await _pipeStream.WriteAsync(frame, ct).ConfigureAwait(false);
        await _pipeStream.FlushAsync(ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Synchronous wrapper for TrySendMessage.
    /// </summary>
    public bool TrySendMessage(IpcMessage message)
    {
        return TrySendMessageAsync(message).GetAwaiter().GetResult();
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

            if (IpcMessage.TryDeserialize(frame, frame.Length, out var message))
            {
                _lastReadMessage = message;
                return IpcReadResult.Success;
            }

            return IpcReadResult.Malformed;
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
            _pipeStream?.Dispose();
            _pipeStream = null;
        }
    }
}

/// <summary>
/// Kernel-backed process identity reads shared by both IPC sides.
/// </summary>
public static class KernelIdentity
{
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
                return WorkerSupervisor.GetTokenUserSid(tokenHandle.DangerousGetHandle());
            }
        }
        finally
        {
            Kernel32Native.CloseHandle(hProcess);
        }
    }
}
