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
    /// <summary>Upper bound on any single write so a silent peer cannot stall I/O.</summary>
    private static readonly TimeSpan MaxWriteTimeout = TimeSpan.FromSeconds(5);

    private readonly string _pipeName;
    private readonly LaunchCapability _capability;
    private readonly FencingIds _fence;
    private readonly uint _expectedGeneration;
    private uint _expectedChildPid;
    private readonly uint _expectedChildSessionId;
    private readonly string _expectedChildSid;
    private NamedPipeServerStream? _pipeStream;
    private readonly CancellationTokenSource _disposeCts = new();
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
    /// The pipe is restricted to the current user via
    /// <see cref="PipeOptions.CurrentUserOnly"/>; remote clients and other
    /// users are denied at the ACL. Returns the authenticated result.
    /// </summary>
    public async Task<IpcAuthenticationResult> WaitForAuthenticatedConnectionAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            // Single-instance message pipe. CurrentUserOnly restricts the ACL
            // to the creating user; remote clients are denied by the kernel.
            // A session-0 service supervisor that must accept a distinct user
            // worker SID cannot use CurrentUserOnly alone — that deployment
            // requires an explicit PipeSecurity ACL granting only that SID.
            _pipeStream = new NamedPipeServerStream(
                _pipeName,
                PipeDirection.InOut,
                1, // Single instance.
                PipeTransmissionMode.Message,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

            // Wait for connection with timeout.
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            connectCts.CancelAfter(timeout);

            await _pipeStream.WaitForConnectionAsync(connectCts.Token).ConfigureAwait(false);

            // Verify client process ID from kernel (not from payload).
            uint clientPid = GetClientProcessId();
            if (clientPid == 0)
            {
                await TrySendBoundedRejectAsync(HandshakeResponsePayload.ReasonProcessMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.TransportFailure;
            }

            if (_expectedChildPid == 0 || clientPid != _expectedChildPid)
            {
                await TrySendBoundedRejectAsync(HandshakeResponsePayload.ReasonProcessMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.ProcessMismatch;
            }

            // Verify client session ID from kernel ProcessIdToSessionId.
            if (!WtsNative.ProcessIdToSessionId(clientPid, out uint clientSessionId))
            {
                await TrySendBoundedRejectAsync(HandshakeResponsePayload.ReasonSessionMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.TransportFailure;
            }

            if (clientSessionId != _expectedChildSessionId)
            {
                await TrySendBoundedRejectAsync(HandshakeResponsePayload.ReasonSessionMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.SessionMismatch;
            }

            // Verify client token SID from kernel OpenProcessToken.
            if (!TryVerifyProcessTokenSid(clientPid))
            {
                await TrySendBoundedRejectAsync(HandshakeResponsePayload.ReasonTokenMismatch).ConfigureAwait(false);
                return IpcAuthenticationResult.TokenMismatch;
            }

            // Read handshake request from worker.
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
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
    /// Send a message to the connected worker. Every write is bounded: a
    /// silent or wedged peer cannot stall the caller. If
    /// <paramref name="ct"/> is unsignaled, <see cref="MaxWriteTimeout"/>
    /// still applies.
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
    /// Synchronous wrapper for TrySendMessage. Always bounded by the timeout.
    /// </summary>
    public bool TrySendMessage(IpcMessage message, TimeSpan timeout)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_disposeCts.Token);
        cts.CancelAfter(timeout <= TimeSpan.Zero || timeout > MaxWriteTimeout ? MaxWriteTimeout : timeout);
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

    /// <summary>Read one framed message and return its parsed value.</summary>
    public async Task<(IpcReadResult Result, IpcMessage Message)> ReadMessageAsync(
        CancellationToken ct)
    {
        IpcReadResult result = await TryReadMessageAsync(ct).ConfigureAwait(false);
        return result == IpcReadResult.Success && _lastReadMessage is { } message
            ? (result, message)
            : (result, default);
    }

    /// <summary>
    /// Read one message and require it to be <paramref name="expectedType"/>
    /// carrying a fence stamp that matches this channel. Unknown types and
    /// fence mismatches fail closed.
    /// </summary>
    public async Task<(IpcReadResult Result, IpcMessage Message)> ReadFencedMessageAsync(
        IpcMessageType expectedType,
        CancellationToken ct)
    {
        var (result, read) = await ReadMessageAsync(ct).ConfigureAwait(false);
        if (result != IpcReadResult.Success)
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
    /// Bounded best-effort reject used on early-identity failures so the peer
    /// is not left waiting for a handshake reply that never comes. Never
    /// throws; a silent peer only burns at most <see cref="MaxWriteTimeout"/>.
    /// </summary>
    private async Task TrySendBoundedRejectAsync(byte reason)
    {
        try
        {
            await SendHandshakeResponseAsync(false, reason, _disposeCts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best-effort only — the reject path must not throw.
        }
    }

    private async Task SendHandshakeResponseAsync(bool accepted, byte reason, CancellationToken ct = default)
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

        await TrySendMessageAsync(msg, ct).ConfigureAwait(false);
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
            // Cancel in-flight I/O first so pending reads/writes unblock.
            try { _disposeCts.Cancel(); } catch (ObjectDisposedException) { }
            Disconnect();
            _pipeStream?.Dispose();
            _pipeStream = null;
            _disposeCts.Dispose();
        }
    }
}
