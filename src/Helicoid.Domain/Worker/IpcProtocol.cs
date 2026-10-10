namespace Helicoid.Domain.Worker;

/// <summary>
/// Per-launch capability nonce. 32 bytes of cryptographic randomness generated
/// by the supervisor and passed to the child worker via a private channel
/// (inherited handle or environment variable that is not exposed in argv/logs).
///
/// Bytes is immutable: the getter returns a defensive copy to prevent external mutation.
/// </summary>
public readonly record struct LaunchCapability
{
    /// <summary>Byte length of the capability nonce.</summary>
    public const int Length = 32;

    /// <summary>
    /// Backing storage for the capability bytes. Private to prevent external mutation.
    /// </summary>
    private readonly byte[] _bytes;

    /// <summary>
    /// Capability bytes. Returns a defensive copy to prevent external mutation.
    /// Never logged, serialized to argv, or exposed in public diagnostics.
    /// </summary>
    public byte[] Bytes => _bytes is null ? Array.Empty<byte>() : (byte[])_bytes.Clone();

    /// <summary>
    /// Internal accessor that does not copy (for trusted internal use only).
    /// </summary>
    internal byte[] BytesInternal => _bytes ?? Array.Empty<byte>();

    /// <summary>
    /// Private constructor with defensive copy.
    /// </summary>
    private LaunchCapability(byte[] bytes)
    {
        _bytes = (byte[])bytes.Clone();
    }

    /// <summary>
    /// Generate a new random capability nonce.
    /// </summary>
    public static LaunchCapability Generate()
    {
        byte[] bytes = new byte[Length];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return new LaunchCapability(bytes);
    }

    /// <summary>
    /// Create from existing bytes. Validates length and makes a defensive copy.
    /// </summary>
    public static LaunchCapability FromBytes(byte[] bytes)
    {
        if (bytes is null || bytes.Length != Length)
        {
            throw new ArgumentException($"Capability must be exactly {Length} bytes.", nameof(bytes));
        }

        return new LaunchCapability(bytes);
    }

    /// <summary>
    /// Constant-time comparison to prevent timing attacks.
    /// Uses internal accessor to avoid defensive copy during comparison.
    /// </summary>
    public bool Matches(LaunchCapability other)
    {
        byte[] a = BytesInternal;
        byte[] b = other.BytesInternal;
        if (a.Length != Length || b.Length != Length)
        {
            return false;
        }

        int diff = 0;
        for (int i = 0; i < Length; i++)
        {
            diff |= a[i] ^ b[i];
        }

        return diff == 0;
    }
}

/// <summary>
/// Process identity binding for IPC authentication. Captures the OS-level
/// identity of the connecting process so the supervisor can verify the peer
/// is the expected child and not a different process running under the same user.
/// </summary>
public readonly record struct ProcessIdentity
{
    /// <summary>OS process ID.</summary>
    public required uint ProcessId { get; init; }

    /// <summary>OS session ID (WTS session).</summary>
    public required uint SessionId { get; init; }

    /// <summary>
    /// Token user SID as a string (S-1-5-...). Used for matching, never logged.
    /// </summary>
    public required string TokenSid { get; init; }

    public bool Matches(ProcessIdentity other)
        => ProcessId == other.ProcessId
        && SessionId == other.SessionId
        && string.Equals(TokenSid, other.TokenSid, StringComparison.Ordinal);
}

/// <summary>
/// IPC message types exchanged between supervisor and worker.
/// </summary>
public enum IpcMessageType : byte
{
    /// <summary>Worker sends after connecting with its capability nonce.</summary>
    HandshakeRequest = 1,

    /// <summary>Supervisor responds with acceptance/rejection.</summary>
    HandshakeResponse = 2,

    /// <summary>Supervisor assigns work to the worker.</summary>
    WorkAssignment = 3,

    /// <summary>Worker acknowledges work receipt.</summary>
    WorkAck = 4,

    /// <summary>Worker reports status.</summary>
    StatusReport = 5,

    /// <summary>Either side requests clean shutdown.</summary>
    Shutdown = 6,

    /// <summary>Heartbeat ping.</summary>
    HeartbeatPing = 7,

    /// <summary>Heartbeat pong.</summary>
    HeartbeatPong = 8,
}

/// <summary>
/// Post-handshake operation codes. Unknown codes fail closed; capture, input,
/// and network operations are intentionally absent until an admitted ABI exists.
/// </summary>
public enum WorkOperationCode : byte
{
    /// <summary>Metadata-only status query. No pixels, input, or network.</summary>
    MetadataStatusQuery = 1,
}

/// <summary>
/// Worker status codes carried on <see cref="IpcMessageType.StatusReport"/>.
/// Unknown codes fail closed.
/// </summary>
public enum WorkerStatusCode : byte
{
    /// <summary>Worker is idle and accepting assignments.</summary>
    Idle = 0,

    /// <summary>Worker is processing a metadata assignment.</summary>
    Busy = 1,
}

/// <summary>
/// IPC message frame. Bounded to <see cref="MaxPayloadSize"/> to prevent
/// oversized allocations.
/// </summary>
public readonly record struct IpcMessage
{
    /// <summary>Maximum payload size per frame.</summary>
    public const int MaxPayloadSize = 65000;

    /// <summary>Frame header size (type + length).</summary>
    public const int HeaderSize = 5;

    /// <summary>Maximum total frame size.</summary>
    public const int MaxFrameSize = HeaderSize + MaxPayloadSize;

    /// <summary>Message type discriminator.</summary>
    public required IpcMessageType Type { get; init; }

    /// <summary>
    /// Payload bytes. Null for header-only messages (shutdown, heartbeat).
    /// </summary>
    public byte[]? Payload { get; init; }

    /// <summary>
    /// Serialize this message to a byte frame for transmission.
    /// </summary>
    public byte[] Serialize()
    {
        int payloadLen = Payload?.Length ?? 0;
        if (payloadLen > MaxPayloadSize)
        {
            throw new InvalidOperationException("Payload exceeds maximum frame size.");
        }

        byte[] frame = new byte[HeaderSize + payloadLen];
        frame[0] = (byte)Type;
        BitConverter.TryWriteBytes(frame.AsSpan(1, 4), payloadLen);
        if (Payload is not null && payloadLen > 0)
        {
            Buffer.BlockCopy(Payload, 0, frame, HeaderSize, payloadLen);
        }

        return frame;
    }

    /// <summary>
    /// Try to deserialize a message from raw bytes read from the pipe.
    /// Returns false if the frame is malformed or oversized.
    /// </summary>
    public static bool TryDeserialize(byte[] data, int length, out IpcMessage message)
    {
        message = default;

        if (data is null || length < HeaderSize || length > MaxFrameSize)
        {
            return false;
        }

        var type = (IpcMessageType)data[0];
        if (!Enum.IsDefined(type))
        {
            return false;
        }

        int payloadLen = BitConverter.ToInt32(data, 1);
        if (payloadLen < 0 || payloadLen > MaxPayloadSize || HeaderSize + payloadLen != length)
        {
            return false;
        }

        byte[]? payload = null;
        if (payloadLen > 0)
        {
            payload = new byte[payloadLen];
            Buffer.BlockCopy(data, HeaderSize, payload, 0, payloadLen);
        }

        message = new IpcMessage { Type = type, Payload = payload };
        return true;
    }
}

/// <summary>
/// Per-message fencing stamp. Mandatory on every post-handshake message.
/// Carries boot ID (supervisor instance), launch ID (worker instance), and
/// desktop generation. A stamp that does not match the receiver's current
/// fence fails closed — a stale callback can never act on a replacement.
/// </summary>
public readonly record struct FenceStamp
{
    /// <summary>Serialized size: boot(16) + launch(16) + generation(4).</summary>
    public const int Size = FencingIds.IdLength + FencingIds.IdLength + 4;

    /// <summary>Supervisor boot ID.</summary>
    public required byte[] BootId { get; init; }

    /// <summary>Worker launch ID.</summary>
    public required byte[] LaunchId { get; init; }

    /// <summary>Desktop generation at stamp time.</summary>
    public required uint Generation { get; init; }

    /// <summary>Serialize to a fixed 36-byte block.</summary>
    public byte[] Serialize()
    {
        byte[] data = new byte[Size];
        if (BootId is null || BootId.Length != FencingIds.IdLength
            || LaunchId is null || LaunchId.Length != FencingIds.IdLength)
        {
            throw new InvalidOperationException("Fence stamp requires 16-byte boot and launch IDs.");
        }

        Buffer.BlockCopy(BootId, 0, data, 0, FencingIds.IdLength);
        Buffer.BlockCopy(LaunchId, 0, data, FencingIds.IdLength, FencingIds.IdLength);
        BitConverter.TryWriteBytes(data.AsSpan(FencingIds.IdLength * 2, 4), Generation);
        return data;
    }

    /// <summary>
    /// Strict parse. Missing, short, or wrong-length IDs are rejected —
    /// fencing is never best-effort.
    /// </summary>
    public static bool TryDeserialize(byte[]? data, out FenceStamp stamp)
    {
        stamp = default;
        if (data is null || data.Length != Size)
        {
            return false;
        }

        byte[] boot = new byte[FencingIds.IdLength];
        byte[] launch = new byte[FencingIds.IdLength];
        Buffer.BlockCopy(data, 0, boot, 0, FencingIds.IdLength);
        Buffer.BlockCopy(data, FencingIds.IdLength, launch, 0, FencingIds.IdLength);
        uint generation = BitConverter.ToUInt32(data, FencingIds.IdLength * 2);

        stamp = new FenceStamp { BootId = boot, LaunchId = launch, Generation = generation };
        return true;
    }

    /// <summary>
    /// Constant-time match of boot and launch IDs plus exact generation.
    /// Zero or wrong-length IDs never match — no stale stamp can act.
    /// </summary>
    public bool Matches(in FenceStamp other)
    {
        if (!FencingIds.IsUsableId(BootId) || !FencingIds.IsUsableId(LaunchId)
            || !FencingIds.IsUsableId(other.BootId) || !FencingIds.IsUsableId(other.LaunchId))
        {
            return false;
        }

        int diff = Generation == other.Generation ? 0 : 1;
        for (int i = 0; i < FencingIds.IdLength; i++)
        {
            diff |= BootId[i] ^ other.BootId[i];
            diff |= LaunchId[i] ^ other.LaunchId[i];
        }

        return diff == 0;
    }
}

/// <summary>
/// Handshake request payload sent by the worker. Boot ID, launch ID, session
/// identity, token SID, and desktop generation are mandatory: a missing or
/// malformed field denies the connection.
/// </summary>
public readonly record struct HandshakeRequestPayload
{
    /// <summary>Minimum encoded size (empty SID rejected earlier).</summary>
    public const int MinSize = 78 + 3;

    /// <summary>Maximum encoded size.</summary>
    public const int MaxSize = 78 + 192;

    /// <summary>Maximum accepted token SID string length.</summary>
    public const int MaxTokenSidLength = 192;

    public required uint WorkerProcessId { get; init; }
    public required uint WorkerSessionId { get; init; }
    public required byte[] CapabilityNonce { get; init; }
    public required byte[] BootId { get; init; }
    public required byte[] LaunchId { get; init; }
    public required uint DesktopGeneration { get; init; }

    /// <summary>Token user SID string (S-1-5-...). Never logged.</summary>
    public required string TokenSid { get; init; }

    /// <summary>
    /// Serialize to bytes:
    /// PID(4) Session(4) Boot(16) Launch(16) Gen(4) Nonce(32) SidLen(2) Sid.
    /// </summary>
    public byte[] Serialize()
    {
        if (CapabilityNonce is null || CapabilityNonce.Length != LaunchCapability.Length)
        {
            throw new InvalidOperationException("Capability nonce must be 32 bytes.");
        }

        if (BootId is null || BootId.Length != FencingIds.IdLength
            || LaunchId is null || LaunchId.Length != FencingIds.IdLength)
        {
            throw new InvalidOperationException("Fence IDs must be 16 bytes.");
        }

        if (!TryValidateTokenSid(TokenSid, out byte[] sidBytes))
        {
            throw new InvalidOperationException("Token SID is missing or malformed.");
        }

        byte[] data = new byte[78 + sidBytes.Length];
        BitConverter.TryWriteBytes(data.AsSpan(0, 4), WorkerProcessId);
        BitConverter.TryWriteBytes(data.AsSpan(4, 4), WorkerSessionId);
        Buffer.BlockCopy(BootId, 0, data, 8, FencingIds.IdLength);
        Buffer.BlockCopy(LaunchId, 0, data, 24, FencingIds.IdLength);
        BitConverter.TryWriteBytes(data.AsSpan(40, 4), DesktopGeneration);
        Buffer.BlockCopy(CapabilityNonce, 0, data, 44, LaunchCapability.Length);
        BitConverter.TryWriteBytes(data.AsSpan(76, 2), (ushort)sidBytes.Length);
        Buffer.BlockCopy(sidBytes, 0, data, 78, sidBytes.Length);
        return data;
    }

    /// <summary>
    /// Strict parse. Any missing, short, or malformed field is rejected.
    /// </summary>
    public static bool TryDeserialize(byte[]? data, out HandshakeRequestPayload payload)
    {
        payload = default;
        if (data is null || data.Length < MinSize || data.Length > MaxSize)
        {
            return false;
        }

        int sidLen = BitConverter.ToUInt16(data, 76);
        if (sidLen < 3 || sidLen > MaxTokenSidLength || 78 + sidLen != data.Length)
        {
            return false;
        }

        string tokenSid = System.Text.Encoding.UTF8.GetString(data, 78, sidLen);
        if (!TryValidateTokenSid(tokenSid, out _))
        {
            return false;
        }

        uint pid = BitConverter.ToUInt32(data, 0);
        uint sid = BitConverter.ToUInt32(data, 4);

        byte[] boot = new byte[FencingIds.IdLength];
        byte[] launch = new byte[FencingIds.IdLength];
        byte[] nonce = new byte[LaunchCapability.Length];
        Buffer.BlockCopy(data, 8, boot, 0, FencingIds.IdLength);
        Buffer.BlockCopy(data, 24, launch, 0, FencingIds.IdLength);
        uint generation = BitConverter.ToUInt32(data, 40);
        Buffer.BlockCopy(data, 44, nonce, 0, LaunchCapability.Length);

        if (pid == 0)
        {
            return false;
        }

        payload = new HandshakeRequestPayload
        {
            WorkerProcessId = pid,
            WorkerSessionId = sid,
            CapabilityNonce = nonce,
            BootId = boot,
            LaunchId = launch,
            DesktopGeneration = generation,
            TokenSid = tokenSid,
        };
        return true;
    }

    /// <summary>
    /// Token SID must look like a Windows SID string and be non-empty.
    /// </summary>
    public static bool TryValidateTokenSid(string? sid, out byte[] sidBytes)
    {
        sidBytes = Array.Empty<byte>();
        if (string.IsNullOrEmpty(sid) || sid.Length < 3 || sid.Length > MaxTokenSidLength)
        {
            return false;
        }

        if (sid[0] != 'S' || sid[1] != '-')
        {
            return false;
        }

        sidBytes = System.Text.Encoding.UTF8.GetBytes(sid);
        return true;
    }
}

/// <summary>
/// Handshake response payload sent by the supervisor. Boot ID, launch ID, and
/// desktop generation are mandatory so the worker can verify the reply belongs
/// to its own launch and generation before acting on it.
/// </summary>
public readonly record struct HandshakeResponsePayload
{
    /// <summary>Serialized size: accepted(1) + reason(1) + boot(16) + launch(16) + gen(4).</summary>
    public const int Size = 38;

    public required bool Accepted { get; init; }

    /// <summary>
    /// Rejection reason (only meaningful when Accepted is false).
    /// </summary>
    public required byte RejectionReason { get; init; }

    /// <summary>Supervisor boot ID (mandatory).</summary>
    public required byte[] BootId { get; init; }

    /// <summary>Worker launch ID (mandatory).</summary>
    public required byte[] LaunchId { get; init; }

    /// <summary>Desktop generation (mandatory).</summary>
    public required uint DesktopGeneration { get; init; }

    /// <summary>Rejection reasons.</summary>
    public const byte ReasonNone = 0;
    public const byte ReasonInvalidCapability = 1;
    public const byte ReasonProcessMismatch = 2;
    public const byte ReasonSessionMismatch = 3;
    public const byte ReasonTokenMismatch = 4;
    public const byte ReasonAlreadyConnected = 5;
    public const byte ReasonOversizedFrame = 6;
    public const byte ReasonFenceMismatch = 7;
    public const byte ReasonMissingIdentity = 8;

    public byte[] Serialize()
    {
        if (BootId is null || BootId.Length != FencingIds.IdLength
            || LaunchId is null || LaunchId.Length != FencingIds.IdLength)
        {
            throw new InvalidOperationException("Fence IDs must be 16 bytes.");
        }

        byte[] data = new byte[Size];
        data[0] = Accepted ? (byte)1 : (byte)0;
        data[1] = RejectionReason;
        Buffer.BlockCopy(BootId, 0, data, 2, FencingIds.IdLength);
        Buffer.BlockCopy(LaunchId, 0, data, 18, FencingIds.IdLength);
        BitConverter.TryWriteBytes(data.AsSpan(34, 4), DesktopGeneration);
        return data;
    }

    /// <summary>
    /// Strict parse. Missing fence fields are rejected — never optional.
    /// </summary>
    public static bool TryDeserialize(byte[]? data, out HandshakeResponsePayload payload)
    {
        payload = default;
        if (data is null || data.Length != Size)
        {
            return false;
        }

        byte[] boot = new byte[FencingIds.IdLength];
        byte[] launch = new byte[FencingIds.IdLength];
        Buffer.BlockCopy(data, 2, boot, 0, FencingIds.IdLength);
        Buffer.BlockCopy(data, 18, launch, 0, FencingIds.IdLength);

        payload = new HandshakeResponsePayload
        {
            Accepted = data[0] != 0,
            RejectionReason = data[1],
            BootId = boot,
            LaunchId = launch,
            DesktopGeneration = BitConverter.ToUInt32(data, 34),
        };
        return true;
    }
}

/// <summary>
/// Payload for <see cref="IpcMessageType.WorkAssignment"/>. Carries a mandatory
/// fence stamp and a known operation code. Unknown operations fail closed.
/// </summary>
public readonly record struct WorkAssignmentPayload
{
    /// <summary>Fixed prefix: fence(36) + op(1) + bodyLen(2).</summary>
    public const int HeaderSize = FenceStamp.Size + 1 + 2;

    /// <summary>Maximum operation body size.</summary>
    public const int MaxBodySize = 1024;

    public required FenceStamp Fence { get; init; }
    public required WorkOperationCode Operation { get; init; }
    public byte[]? Body { get; init; }

    public byte[] Serialize()
    {
        if (!Enum.IsDefined(Operation))
        {
            throw new InvalidOperationException("Unknown work operation code.");
        }

        int bodyLen = Body?.Length ?? 0;
        if (bodyLen > MaxBodySize)
        {
            throw new InvalidOperationException("Work assignment body exceeds bound.");
        }

        byte[] data = new byte[HeaderSize + bodyLen];
        Buffer.BlockCopy(Fence.Serialize(), 0, data, 0, FenceStamp.Size);
        data[FenceStamp.Size] = (byte)Operation;
        BitConverter.TryWriteBytes(data.AsSpan(FenceStamp.Size + 1, 2), (ushort)bodyLen);
        if (bodyLen > 0)
        {
            Buffer.BlockCopy(Body!, 0, data, HeaderSize, bodyLen);
        }

        return data;
    }

    /// <summary>
    /// Strict parse. Unknown operation codes and malformed fences fail closed.
    /// </summary>
    public static bool TryDeserialize(byte[]? data, out WorkAssignmentPayload payload)
    {
        payload = default;
        if (data is null || data.Length < HeaderSize || data.Length > HeaderSize + MaxBodySize)
        {
            return false;
        }

        byte[] fenceBytes = new byte[FenceStamp.Size];
        Buffer.BlockCopy(data, 0, fenceBytes, 0, FenceStamp.Size);
        if (!FenceStamp.TryDeserialize(fenceBytes, out var fence))
        {
            return false;
        }

        var op = (WorkOperationCode)data[FenceStamp.Size];
        if (!Enum.IsDefined(op))
        {
            return false;
        }

        int bodyLen = BitConverter.ToUInt16(data, FenceStamp.Size + 1);
        if (bodyLen > MaxBodySize || HeaderSize + bodyLen != data.Length)
        {
            return false;
        }

        byte[]? body = null;
        if (bodyLen > 0)
        {
            body = new byte[bodyLen];
            Buffer.BlockCopy(data, HeaderSize, body, 0, bodyLen);
        }

        payload = new WorkAssignmentPayload { Fence = fence, Operation = op, Body = body };
        return true;
    }
}

/// <summary>
/// Payload for <see cref="IpcMessageType.WorkAck"/>. Mandatory fence plus the
/// acknowledged operation code.
/// </summary>
public readonly record struct WorkAckPayload
{
    /// <summary>Serialized size: fence(36) + op(1).</summary>
    public const int Size = FenceStamp.Size + 1;

    public required FenceStamp Fence { get; init; }
    public required WorkOperationCode Operation { get; init; }

    public byte[] Serialize()
    {
        if (!Enum.IsDefined(Operation))
        {
            throw new InvalidOperationException("Unknown work operation code.");
        }

        byte[] data = new byte[Size];
        Buffer.BlockCopy(Fence.Serialize(), 0, data, 0, FenceStamp.Size);
        data[FenceStamp.Size] = (byte)Operation;
        return data;
    }

    public static bool TryDeserialize(byte[]? data, out WorkAckPayload payload)
    {
        payload = default;
        if (data is null || data.Length != Size)
        {
            return false;
        }

        byte[] fenceBytes = new byte[FenceStamp.Size];
        Buffer.BlockCopy(data, 0, fenceBytes, 0, FenceStamp.Size);
        if (!FenceStamp.TryDeserialize(fenceBytes, out var fence))
        {
            return false;
        }

        var op = (WorkOperationCode)data[FenceStamp.Size];
        if (!Enum.IsDefined(op))
        {
            return false;
        }

        payload = new WorkAckPayload { Fence = fence, Operation = op };
        return true;
    }
}

/// <summary>
/// Payload for <see cref="IpcMessageType.StatusReport"/>. Mandatory fence plus
/// a known worker status code. Unknown codes fail closed.
/// </summary>
public readonly record struct StatusReportPayload
{
    /// <summary>Serialized size: fence(36) + status(1).</summary>
    public const int Size = FenceStamp.Size + 1;

    public required FenceStamp Fence { get; init; }
    public required WorkerStatusCode Status { get; init; }

    public byte[] Serialize()
    {
        if (!Enum.IsDefined(Status))
        {
            throw new InvalidOperationException("Unknown worker status code.");
        }

        byte[] data = new byte[Size];
        Buffer.BlockCopy(Fence.Serialize(), 0, data, 0, FenceStamp.Size);
        data[FenceStamp.Size] = (byte)Status;
        return data;
    }

    public static bool TryDeserialize(byte[]? data, out StatusReportPayload payload)
    {
        payload = default;
        if (data is null || data.Length != Size)
        {
            return false;
        }

        byte[] fenceBytes = new byte[FenceStamp.Size];
        Buffer.BlockCopy(data, 0, fenceBytes, 0, FenceStamp.Size);
        if (!FenceStamp.TryDeserialize(fenceBytes, out var fence))
        {
            return false;
        }

        var status = (WorkerStatusCode)data[FenceStamp.Size];
        if (!Enum.IsDefined(status))
        {
            return false;
        }

        payload = new StatusReportPayload { Fence = fence, Status = status };
        return true;
    }
}
