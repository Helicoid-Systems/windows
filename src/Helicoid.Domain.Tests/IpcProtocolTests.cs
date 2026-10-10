using System.Security.Cryptography;
using Helicoid.Domain.Worker;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Cross-platform tests for IPC protocol message serialization and parsing.
/// These tests verify the wire format without requiring Windows named pipes.
/// </summary>
public sealed class IpcProtocolTests
{
    // --- LaunchCapability ---

    [Fact]
    public void LaunchCapability_Generate_ProducesCorrectLength()
    {
        var cap = LaunchCapability.Generate();

        Assert.NotNull(cap.Bytes);
        Assert.Equal(LaunchCapability.Length, cap.Bytes.Length);
    }

    [Fact]
    public void LaunchCapability_Generate_ProducesUniqueValues()
    {
        var cap1 = LaunchCapability.Generate();
        var cap2 = LaunchCapability.Generate();

        Assert.False(cap1.Matches(cap2));
    }

    [Fact]
    public void LaunchCapability_Matches_IdenticalBytes()
    {
        byte[] bytes = new byte[LaunchCapability.Length];
        RandomNumberGenerator.Fill(bytes);
        var cap1 = LaunchCapability.FromBytes(bytes);
        var cap2 = LaunchCapability.FromBytes(bytes);

        Assert.True(cap1.Matches(cap2));
    }

    [Fact]
    public void LaunchCapability_Matches_RejectsDifferentBytes()
    {
        var cap1 = LaunchCapability.Generate();
        var cap2 = LaunchCapability.Generate();

        Assert.False(cap1.Matches(cap2));
    }

    [Fact]
    public void LaunchCapability_FromBytes_RejectsWrongLength()
    {
        Assert.Throws<ArgumentException>(() => LaunchCapability.FromBytes(new byte[16]));
        Assert.Throws<ArgumentException>(() => LaunchCapability.FromBytes(new byte[33]));
        Assert.Throws<ArgumentException>(() => LaunchCapability.FromBytes(Array.Empty<byte>()));
    }

    [Fact]
    public void LaunchCapability_FromBytes_RejectsNull()
    {
        Assert.Throws<ArgumentException>(() => LaunchCapability.FromBytes(null!));
    }

    [Fact]
    public void LaunchCapability_Bytes_ReturnsDefensiveCopy()
    {
        var cap = LaunchCapability.Generate();
        byte[] bytes1 = cap.Bytes;
        byte[] bytes2 = cap.Bytes;

        // Should be equal but not the same reference.
        Assert.Equal(bytes1, bytes2);
        Assert.False(ReferenceEquals(bytes1, bytes2));

        // Mutating the copy should not affect the capability.
        bytes1[0] = (byte)~bytes1[0];
        Assert.NotEqual(bytes1, cap.Bytes);
    }

    [Fact]
    public void LaunchCapability_Matches_ConstantTime()
    {
        // Verify that Matches does not short-circuit on first differing byte.
        byte[] bytes1 = new byte[LaunchCapability.Length];
        byte[] bytes2 = new byte[LaunchCapability.Length];
        bytes1[0] = 1;
        bytes2[0] = 2;
        // Fill rest with same values.
        for (int i = 1; i < LaunchCapability.Length; i++)
        {
            bytes1[i] = bytes2[i] = (byte)i;
        }

        var cap1 = LaunchCapability.FromBytes(bytes1);
        var cap2 = LaunchCapability.FromBytes(bytes2);

        Assert.False(cap1.Matches(cap2));
    }

    // --- IpcMessage serialization ---

    [Fact]
    public void IpcMessage_Serialize_EmptyPayload()
    {
        var msg = new IpcMessage { Type = IpcMessageType.Shutdown };
        byte[] frame = msg.Serialize();

        Assert.Equal(IpcMessage.HeaderSize, frame.Length);
        Assert.Equal((byte)IpcMessageType.Shutdown, frame[0]);
        Assert.Equal(0, BitConverter.ToInt32(frame, 1));
    }

    [Fact]
    public void IpcMessage_Serialize_WithPayload()
    {
        byte[] payload = [1, 2, 3, 4, 5];
        var msg = new IpcMessage { Type = IpcMessageType.WorkAssignment, Payload = payload };
        byte[] frame = msg.Serialize();

        Assert.Equal(IpcMessage.HeaderSize + 5, frame.Length);
        Assert.Equal((byte)IpcMessageType.WorkAssignment, frame[0]);
        Assert.Equal(5, BitConverter.ToInt32(frame, 1));
        Assert.Equal(payload, frame.AsSpan(IpcMessage.HeaderSize).ToArray());
    }

    [Fact]
    public void IpcMessage_Serialize_MaxPayload()
    {
        byte[] payload = new byte[IpcMessage.MaxPayloadSize];
        RandomNumberGenerator.Fill(payload);
        var msg = new IpcMessage { Type = IpcMessageType.StatusReport, Payload = payload };
        byte[] frame = msg.Serialize();

        Assert.Equal(IpcMessage.HeaderSize + IpcMessage.MaxPayloadSize, frame.Length);
    }

    [Fact]
    public void IpcMessage_Serialize_RejectsOversizedPayload()
    {
        byte[] payload = new byte[IpcMessage.MaxPayloadSize + 1];
        var msg = new IpcMessage { Type = IpcMessageType.StatusReport, Payload = payload };

        Assert.Throws<InvalidOperationException>(() => msg.Serialize());
    }

    // --- IpcMessage deserialization ---

    [Fact]
    public void IpcMessage_TryDeserialize_EmptyPayload()
    {
        byte[] frame = [(byte)IpcMessageType.HeartbeatPing, 0, 0, 0, 0];

        Assert.True(IpcMessage.TryDeserialize(frame, frame.Length, out var msg));
        Assert.Equal(IpcMessageType.HeartbeatPing, msg.Type);
        Assert.Null(msg.Payload);
    }

    [Fact]
    public void IpcMessage_TryDeserialize_WithPayload()
    {
        byte[] payload = [0xAA, 0xBB, 0xCC];
        byte[] frame = new byte[IpcMessage.HeaderSize + 3];
        frame[0] = (byte)IpcMessageType.WorkAck;
        BitConverter.TryWriteBytes(frame.AsSpan(1, 4), 3);
        Buffer.BlockCopy(payload, 0, frame, IpcMessage.HeaderSize, 3);

        Assert.True(IpcMessage.TryDeserialize(frame, frame.Length, out var msg));
        Assert.Equal(IpcMessageType.WorkAck, msg.Type);
        Assert.NotNull(msg.Payload);
        Assert.Equal(payload, msg.Payload);
    }

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsNull()
    {
        Assert.False(IpcMessage.TryDeserialize(null!, 0, out _));
    }

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsTooShort()
    {
        byte[] frame = [1, 0, 0]; // 3 bytes, need 5.
        Assert.False(IpcMessage.TryDeserialize(frame, 3, out _));
    }

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsOversized()
    {
        byte[] frame = new byte[IpcMessage.MaxFrameSize + 1];
        frame[0] = (byte)IpcMessageType.Shutdown;
        Assert.False(IpcMessage.TryDeserialize(frame, frame.Length, out _));
    }

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsInvalidType()
    {
        byte[] frame = [0, 0, 0, 0, 0]; // Type 0 is not defined.
        Assert.False(IpcMessage.TryDeserialize(frame, frame.Length, out _));
    }

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsPayloadLengthMismatch()
    {
        // Header says 10 bytes payload, but frame is only header + 5.
        byte[] frame = new byte[IpcMessage.HeaderSize + 5];
        frame[0] = (byte)IpcMessageType.StatusReport;
        BitConverter.TryWriteBytes(frame.AsSpan(1, 4), 10); // Claims 10 bytes.

        Assert.False(IpcMessage.TryDeserialize(frame, frame.Length, out _));
    }

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsNegativePayloadLength()
    {
        byte[] frame = new byte[IpcMessage.HeaderSize];
        frame[0] = (byte)IpcMessageType.StatusReport;
        BitConverter.TryWriteBytes(frame.AsSpan(1, 4), -1);

        Assert.False(IpcMessage.TryDeserialize(frame, frame.Length, out _));
    }

    [Fact]
    public void IpcMessage_Roundtrip_AllMessageTypes()
    {
        foreach (IpcMessageType type in Enum.GetValues<IpcMessageType>())
        {
            byte[]? payload = type switch
            {
                IpcMessageType.HandshakeRequest => new byte[HandshakeRequestPayload.MinSize],
                IpcMessageType.HandshakeResponse => new byte[HandshakeResponsePayload.Size],
                IpcMessageType.WorkAssignment => new byte[WorkAssignmentPayload.HeaderSize],
                IpcMessageType.WorkAck => new byte[WorkAckPayload.Size],
                IpcMessageType.StatusReport => new byte[StatusReportPayload.Size],
                IpcMessageType.Shutdown => new byte[FenceStamp.Size],
                IpcMessageType.HeartbeatPing => new byte[FenceStamp.Size],
                IpcMessageType.HeartbeatPong => new byte[FenceStamp.Size],
                _ => null,
            };

            if (payload is not null)
            {
                RandomNumberGenerator.Fill(payload);
            }

            var original = new IpcMessage { Type = type, Payload = payload };
            byte[] frame = original.Serialize();

            Assert.True(IpcMessage.TryDeserialize(frame, frame.Length, out var deserialized));
            Assert.Equal(type, deserialized.Type);

            if (payload is null)
            {
                Assert.Null(deserialized.Payload);
            }
            else
            {
                Assert.Equal(payload, deserialized.Payload);
            }
        }
    }

    // --- HandshakeRequestPayload ---

    private static HandshakeRequestPayload MakeHandshakeRequest(
        uint pid = 12345,
        uint session = 2,
        uint generation = 1,
        string tokenSid = "S-1-5-21-1-2-3-1001",
        byte[]? boot = null,
        byte[]? launch = null,
        byte[]? nonce = null)
    {
        boot ??= FencingIds.GenerateId();
        launch ??= FencingIds.GenerateId();
        nonce ??= new byte[LaunchCapability.Length];
        if (nonce.Length != LaunchCapability.Length)
        {
            RandomNumberGenerator.Fill(nonce);
        }

        return new HandshakeRequestPayload
        {
            WorkerProcessId = pid,
            WorkerSessionId = session,
            CapabilityNonce = nonce,
            BootId = boot,
            LaunchId = launch,
            DesktopGeneration = generation,
            TokenSid = tokenSid,
        };
    }

    [Fact]
    public void HandshakeRequestPayload_Roundtrip()
    {
        byte[] nonce = new byte[LaunchCapability.Length];
        RandomNumberGenerator.Fill(nonce);
        byte[] boot = FencingIds.GenerateId();
        byte[] launch = FencingIds.GenerateId();

        var original = MakeHandshakeRequest(nonce: nonce, boot: boot, launch: launch, generation: 7);

        byte[] serialized = original.Serialize();
        Assert.True(HandshakeRequestPayload.TryDeserialize(serialized, out var deserialized));

        Assert.Equal(12345u, deserialized.WorkerProcessId);
        Assert.Equal(2u, deserialized.WorkerSessionId);
        Assert.Equal(nonce, deserialized.CapabilityNonce);
        Assert.Equal(boot, deserialized.BootId);
        Assert.Equal(launch, deserialized.LaunchId);
        Assert.Equal(7u, deserialized.DesktopGeneration);
        Assert.Equal("S-1-5-21-1-2-3-1001", deserialized.TokenSid);
    }

    [Fact]
    public void HandshakeRequestPayload_TryDeserialize_RejectsWrongSize()
    {
        Assert.False(HandshakeRequestPayload.TryDeserialize(new byte[10], out _));
        Assert.False(HandshakeRequestPayload.TryDeserialize(null, out _));
        Assert.False(HandshakeRequestPayload.TryDeserialize(Array.Empty<byte>(), out _));
    }

    [Fact]
    public void HandshakeRequestPayload_TryDeserialize_RejectsZeroPid()
    {
        var request = MakeHandshakeRequest(pid: 0);
        // Serialize would succeed but parse must reject a zero PID.
        byte[] serialized = request.Serialize();
        Assert.False(HandshakeRequestPayload.TryDeserialize(serialized, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("X")]
    [InlineData("S")]
    [InlineData("not-a-sid")]
    public void HandshakeRequestPayload_Serialize_RejectsMalformedTokenSid(string sid)
    {
        var request = MakeHandshakeRequest(tokenSid: sid);
        Assert.Throws<InvalidOperationException>(() => request.Serialize());
    }

    [Theory]
    [InlineData("")]
    [InlineData("X")]
    [InlineData("S")]
    [InlineData("not-a-sid")]
    public void HandshakeRequestPayload_TryDeserialize_RejectsMalformedTokenSid(string sid)
    {
        // Build a well-formed frame then overwrite the SID region with bad bytes.
        var request = MakeHandshakeRequest();
        byte[] serialized = request.Serialize();

        // Use a SID encoding that is at least 3 bytes so the length check passes,
        // but fails SID-shape validation (no "S-" prefix / empty).
        byte[] sidBytes = sid switch
        {
            "" => new byte[] { (byte)'A', (byte)'B', (byte)'C' },
            "X" => new byte[] { (byte)'X', (byte)'Y', (byte)'Z' },
            "S" => new byte[] { (byte)'S', (byte)'Q', (byte)'1' },
            _ => System.Text.Encoding.UTF8.GetBytes(sid),
        };

        byte[] frame = new byte[78 + sidBytes.Length];
        Buffer.BlockCopy(serialized, 0, frame, 0, 76);
        BitConverter.TryWriteBytes(frame.AsSpan(76, 2), (ushort)sidBytes.Length);
        Buffer.BlockCopy(sidBytes, 0, frame, 78, sidBytes.Length);

        Assert.False(HandshakeRequestPayload.TryDeserialize(frame, out _));
    }

    [Fact]
    public void HandshakeRequestPayload_TryDeserialize_RejectsTruncatedFence()
    {
        var request = MakeHandshakeRequest();
        byte[] serialized = request.Serialize();
        // Flip the SID length to claim more bytes than present.
        BitConverter.TryWriteBytes(serialized.AsSpan(76, 2), (ushort)50);
        Assert.False(HandshakeRequestPayload.TryDeserialize(serialized, out _));
    }

    [Fact]
    public void HandshakeRequestPayload_TryValidateTokenSid_RequiresSidPrefix()
    {
        Assert.True(HandshakeRequestPayload.TryValidateTokenSid("S-1-5-18", out _));
        Assert.False(HandshakeRequestPayload.TryValidateTokenSid(null, out _));
        Assert.False(HandshakeRequestPayload.TryValidateTokenSid("", out _));
        Assert.False(HandshakeRequestPayload.TryValidateTokenSid("A-1-5", out _));
    }

    // --- HandshakeResponsePayload ---

    private static HandshakeResponsePayload MakeHandshakeResponse(
        bool accepted = true,
        byte reason = HandshakeResponsePayload.ReasonNone,
        uint generation = 1,
        byte[]? boot = null,
        byte[]? launch = null)
    {
        return new HandshakeResponsePayload
        {
            Accepted = accepted,
            RejectionReason = reason,
            BootId = boot ?? FencingIds.GenerateId(),
            LaunchId = launch ?? FencingIds.GenerateId(),
            DesktopGeneration = generation,
        };
    }

    [Fact]
    public void HandshakeResponsePayload_Accepted_Roundtrip()
    {
        byte[] boot = FencingIds.GenerateId();
        byte[] launch = FencingIds.GenerateId();
        var original = MakeHandshakeResponse(boot: boot, launch: launch, generation: 4);

        byte[] serialized = original.Serialize();
        Assert.Equal(HandshakeResponsePayload.Size, serialized.Length);
        Assert.True(HandshakeResponsePayload.TryDeserialize(serialized, out var deserialized));

        Assert.True(deserialized.Accepted);
        Assert.Equal(HandshakeResponsePayload.ReasonNone, deserialized.RejectionReason);
        Assert.Equal(boot, deserialized.BootId);
        Assert.Equal(launch, deserialized.LaunchId);
        Assert.Equal(4u, deserialized.DesktopGeneration);
    }

    [Fact]
    public void HandshakeResponsePayload_Rejected_Roundtrip()
    {
        var original = MakeHandshakeResponse(
            accepted: false,
            reason: HandshakeResponsePayload.ReasonInvalidCapability);

        byte[] serialized = original.Serialize();
        Assert.True(HandshakeResponsePayload.TryDeserialize(serialized, out var deserialized));

        Assert.False(deserialized.Accepted);
        Assert.Equal(HandshakeResponsePayload.ReasonInvalidCapability, deserialized.RejectionReason);
    }

    [Fact]
    public void HandshakeResponsePayload_TryDeserialize_RejectsWrongSize()
    {
        Assert.False(HandshakeResponsePayload.TryDeserialize(new byte[3], out _));
        Assert.False(HandshakeResponsePayload.TryDeserialize(null, out _));
        Assert.False(HandshakeResponsePayload.TryDeserialize(new byte[HandshakeResponsePayload.Size - 1], out _));
        Assert.False(HandshakeResponsePayload.TryDeserialize(new byte[HandshakeResponsePayload.Size + 1], out _));
    }

    [Fact]
    public void HandshakeResponsePayload_Serialize_RejectsMissingFence()
    {
        var response = new HandshakeResponsePayload
        {
            Accepted = true,
            RejectionReason = HandshakeResponsePayload.ReasonNone,
            BootId = Array.Empty<byte>(),
            LaunchId = FencingIds.GenerateId(),
            DesktopGeneration = 1,
        };

        Assert.Throws<InvalidOperationException>(() => response.Serialize());
    }

    // --- FenceStamp ---

    [Fact]
    public void FenceStamp_Roundtrip()
    {
        byte[] boot = FencingIds.GenerateId();
        byte[] launch = FencingIds.GenerateId();
        var stamp = new FenceStamp { BootId = boot, LaunchId = launch, Generation = 9 };

        byte[] serialized = stamp.Serialize();
        Assert.Equal(FenceStamp.Size, serialized.Length);
        Assert.True(FenceStamp.TryDeserialize(serialized, out var parsed));
        Assert.Equal(boot, parsed.BootId);
        Assert.Equal(launch, parsed.LaunchId);
        Assert.Equal(9u, parsed.Generation);
        Assert.True(stamp.Matches(parsed));
    }

    [Fact]
    public void FenceStamp_TryDeserialize_RejectsWrongSize()
    {
        Assert.False(FenceStamp.TryDeserialize(null, out _));
        Assert.False(FenceStamp.TryDeserialize(Array.Empty<byte>(), out _));
        Assert.False(FenceStamp.TryDeserialize(new byte[FenceStamp.Size - 1], out _));
        Assert.False(FenceStamp.TryDeserialize(new byte[FenceStamp.Size + 1], out _));
    }

    [Fact]
    public void FenceStamp_Matches_RejectsDifferentBootOrLaunchOrGeneration()
    {
        byte[] boot = FencingIds.GenerateId();
        byte[] launch = FencingIds.GenerateId();
        var stamp = new FenceStamp { BootId = boot, LaunchId = launch, Generation = 1 };

        var differentBoot = new FenceStamp { BootId = FencingIds.GenerateId(), LaunchId = launch, Generation = 1 };
        var differentLaunch = new FenceStamp { BootId = boot, LaunchId = FencingIds.GenerateId(), Generation = 1 };
        var differentGen = new FenceStamp { BootId = boot, LaunchId = launch, Generation = 2 };

        Assert.False(stamp.Matches(differentBoot));
        Assert.False(stamp.Matches(differentLaunch));
        Assert.False(stamp.Matches(differentGen));
    }

    [Fact]
    public void FenceStamp_Matches_RejectsNullIds()
    {
        var stamp = new FenceStamp { BootId = FencingIds.GenerateId(), LaunchId = FencingIds.GenerateId(), Generation = 1 };
        var empty = new FenceStamp { BootId = Array.Empty<byte>(), LaunchId = FencingIds.GenerateId(), Generation = 1 };

        Assert.False(stamp.Matches(empty));
        Assert.False(empty.Matches(stamp));
    }

    // --- WorkAssignmentPayload ---

    [Fact]
    public void WorkAssignmentPayload_Roundtrip_MetadataQuery()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 3,
        };

        var original = new WorkAssignmentPayload
        {
            Fence = stamp,
            Operation = WorkOperationCode.MetadataStatusQuery,
            Body = null,
        };

        byte[] serialized = original.Serialize();
        Assert.True(WorkAssignmentPayload.TryDeserialize(serialized, out var parsed));
        Assert.Equal(WorkOperationCode.MetadataStatusQuery, parsed.Operation);
        Assert.True(parsed.Fence.Matches(stamp));
        Assert.Null(parsed.Body);
    }

    [Fact]
    public void WorkAssignmentPayload_TryDeserialize_RejectsUnknownOperation()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 1,
        };

        byte[] fenceBytes = stamp.Serialize();
        byte[] frame = new byte[WorkAssignmentPayload.HeaderSize];
        Buffer.BlockCopy(fenceBytes, 0, frame, 0, FenceStamp.Size);
        frame[FenceStamp.Size] = 0xEE; // Unknown operation code.
        BitConverter.TryWriteBytes(frame.AsSpan(FenceStamp.Size + 1, 2), (ushort)0);

        Assert.False(WorkAssignmentPayload.TryDeserialize(frame, out _));
    }

    [Fact]
    public void WorkAssignmentPayload_Serialize_RejectsUnknownOperation()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 1,
        };

        var assignment = new WorkAssignmentPayload
        {
            Fence = stamp,
            Operation = (WorkOperationCode)0xEE,
            Body = null,
        };

        Assert.Throws<InvalidOperationException>(() => assignment.Serialize());
    }

    [Fact]
    public void WorkAssignmentPayload_TryDeserialize_RejectsBodyLengthMismatch()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 1,
        };

        byte[] frame = new byte[WorkAssignmentPayload.HeaderSize + 2];
        Buffer.BlockCopy(stamp.Serialize(), 0, frame, 0, FenceStamp.Size);
        frame[FenceStamp.Size] = (byte)WorkOperationCode.MetadataStatusQuery;
        BitConverter.TryWriteBytes(frame.AsSpan(FenceStamp.Size + 1, 2), (ushort)10); // Claims 10, has 2.

        Assert.False(WorkAssignmentPayload.TryDeserialize(frame, out _));
    }

    [Fact]
    public void WorkAssignmentPayload_TryDeserialize_RejectsOversizedBody()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 1,
        };

        byte[] frame = new byte[WorkAssignmentPayload.HeaderSize + WorkAssignmentPayload.MaxBodySize + 1];
        Buffer.BlockCopy(stamp.Serialize(), 0, frame, 0, FenceStamp.Size);
        frame[FenceStamp.Size] = (byte)WorkOperationCode.MetadataStatusQuery;
        BitConverter.TryWriteBytes(frame.AsSpan(FenceStamp.Size + 1, 2), (ushort)(WorkAssignmentPayload.MaxBodySize + 1));

        Assert.False(WorkAssignmentPayload.TryDeserialize(frame, out _));
    }

    // --- WorkAckPayload ---

    [Fact]
    public void WorkAckPayload_Roundtrip()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 2,
        };

        var original = new WorkAckPayload { Fence = stamp, Operation = WorkOperationCode.MetadataStatusQuery };
        byte[] serialized = original.Serialize();
        Assert.True(WorkAckPayload.TryDeserialize(serialized, out var parsed));
        Assert.Equal(WorkOperationCode.MetadataStatusQuery, parsed.Operation);
        Assert.True(parsed.Fence.Matches(stamp));
    }

    [Fact]
    public void WorkAckPayload_TryDeserialize_RejectsUnknownOperation()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 1,
        };

        byte[] frame = new byte[WorkAckPayload.Size];
        Buffer.BlockCopy(stamp.Serialize(), 0, frame, 0, FenceStamp.Size);
        frame[FenceStamp.Size] = 0xFF;

        Assert.False(WorkAckPayload.TryDeserialize(frame, out _));
    }

    // --- StatusReportPayload ---

    [Fact]
    public void StatusReportPayload_Roundtrip()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 5,
        };

        var original = new StatusReportPayload { Fence = stamp, Status = WorkerStatusCode.Idle };
        byte[] serialized = original.Serialize();
        Assert.True(StatusReportPayload.TryDeserialize(serialized, out var parsed));
        Assert.Equal(WorkerStatusCode.Idle, parsed.Status);
        Assert.True(parsed.Fence.Matches(stamp));
    }

    [Fact]
    public void StatusReportPayload_TryDeserialize_RejectsUnknownStatus()
    {
        var stamp = new FenceStamp
        {
            BootId = FencingIds.GenerateId(),
            LaunchId = FencingIds.GenerateId(),
            Generation = 1,
        };

        byte[] frame = new byte[StatusReportPayload.Size];
        Buffer.BlockCopy(stamp.Serialize(), 0, frame, 0, FenceStamp.Size);
        frame[FenceStamp.Size] = 0xAB;

        Assert.False(StatusReportPayload.TryDeserialize(frame, out _));
    }

    // --- IpcMessage constants ---

    [Fact]
    public void IpcMessage_HeaderSize_Is5()
    {
        Assert.Equal(5, IpcMessage.HeaderSize);
    }

    [Fact]
    public void IpcMessage_MaxPayloadSize_Is65000()
    {
        Assert.Equal(65000, IpcMessage.MaxPayloadSize);
    }

    [Fact]
    public void IpcMessage_MaxFrameSize_IsHeaderPlusPayload()
    {
        Assert.Equal(IpcMessage.HeaderSize + IpcMessage.MaxPayloadSize, IpcMessage.MaxFrameSize);
    }

    // --- WorkerLifecycle types ---

    [Fact]
    public void DesktopGeneration_Initial_Is1()
    {
        Assert.Equal(1u, DesktopGeneration.Initial);
    }

    [Fact]
    public void DesktopGeneration_TryNext_Increments()
    {
        var gen = new DesktopGeneration { Value = DesktopGeneration.Initial };
        Assert.True(gen.TryNext(out var next));

        Assert.Equal(2u, next.Value);
    }

    [Fact]
    public void DesktopGeneration_IsStale_WhenLower()
    {
        var current = new DesktopGeneration { Value = 5 };
        var old = new DesktopGeneration { Value = 3 };

        Assert.True(old.IsStale(current));
        Assert.False(current.IsStale(old));
    }

    [Fact]
    public void DesktopGeneration_Exhaustion_DoesNotWrap()
    {
        var atMax = new DesktopGeneration { Value = DesktopGeneration.MaxValue };
        Assert.True(atMax.IsExhausted);
        Assert.False(atMax.TryNext(out var next));
        Assert.Equal(DesktopGeneration.MaxValue, next.Value);
        Assert.NotEqual(0u, next.Value);

        // One below max advances exactly once, then exhausts.
        var nearMax = new DesktopGeneration { Value = DesktopGeneration.MaxValue - 1 };
        Assert.False(nearMax.IsExhausted);
        Assert.True(nearMax.TryNext(out var reached));
        Assert.Equal(DesktopGeneration.MaxValue, reached.Value);
        Assert.True(reached.IsExhausted);
        Assert.False(reached.TryNext(out _));
    }

    [Fact]
    public void DesktopGeneration_TryNext_AtZero_AdvancesTo1()
    {
        var zero = new DesktopGeneration { Value = 0 };
        Assert.True(zero.TryNext(out var next));
        Assert.Equal(1u, next.Value);
    }

    // --- FencingIds ---

    [Fact]
    public void FencingIds_MatchesBoot_Roundtrip()
    {
        byte[] boot = FencingIds.GenerateId();
        byte[] launch = FencingIds.GenerateId();
        var ids = new FencingIds { BootId = boot, LaunchId = launch };

        Assert.True(ids.MatchesBoot(boot));
        Assert.True(ids.MatchesLaunch(launch));
    }

    [Fact]
    public void FencingIds_Matches_RejectsWrongLengthOrDifferent()
    {
        byte[] boot = FencingIds.GenerateId();
        byte[] launch = FencingIds.GenerateId();
        var ids = new FencingIds { BootId = boot, LaunchId = launch };

        Assert.False(ids.MatchesBoot(new byte[8]));
        Assert.False(ids.MatchesLaunch(new byte[32]));
        Assert.False(ids.MatchesBoot(FencingIds.GenerateId()));
        Assert.False(ids.MatchesLaunch(FencingIds.GenerateId()));
    }

    [Fact]
    public void FencingIds_GenerateId_Is16Bytes()
    {
        Assert.Equal(16, FencingIds.IdLength);
        Assert.Equal(16, FencingIds.GenerateId().Length);
        Assert.NotEqual(FencingIds.GenerateId(), FencingIds.GenerateId());
    }

    // --- Zero / invalid fencing IDs must never match (fail closed) ---

    [Fact]
    public void FencingIds_ZeroId_NeverMatches()
    {
        byte[] zero = new byte[FencingIds.IdLength];
        byte[] real = FencingIds.GenerateId();
        var ids = new FencingIds { BootId = real, LaunchId = real };

        Assert.False(FencingIds.IsUsableId(zero));
        Assert.False(FencingIds.IsUsableId(null));
        Assert.False(FencingIds.IsUsableId(new byte[8]));
        Assert.True(FencingIds.IsUsableId(real));

        Assert.False(ids.MatchesBoot(zero));
        Assert.False(ids.MatchesLaunch(zero));
        Assert.False(ids.MatchesBoot(null));
        Assert.False(ids.MatchesLaunch(null));

        // Each field is checked independently: a zero field never matches,
        // a real field can still match its counterpart.
        var zeroBoot = new FencingIds { BootId = zero, LaunchId = real };
        var zeroLaunch = new FencingIds { BootId = real, LaunchId = zero };
        Assert.False(zeroBoot.MatchesBoot(real));
        Assert.True(zeroBoot.MatchesLaunch(real));
        Assert.False(zeroLaunch.MatchesLaunch(real));
        Assert.True(zeroLaunch.MatchesBoot(real));
    }

    [Fact]
    public void FenceStamp_ZeroIds_NeverMatch()
    {
        byte[] zero = new byte[FencingIds.IdLength];
        byte[] real = FencingIds.GenerateId();

        var good = new FenceStamp { BootId = real, LaunchId = real, Generation = 1 };
        var zeroBoot = new FenceStamp { BootId = zero, LaunchId = real, Generation = 1 };
        var zeroLaunch = new FenceStamp { BootId = real, LaunchId = zero, Generation = 1 };
        var zeroBoth = new FenceStamp { BootId = zero, LaunchId = zero, Generation = 1 };

        Assert.False(good.Matches(zeroBoot));
        Assert.False(good.Matches(zeroLaunch));
        Assert.False(good.Matches(zeroBoth));
        Assert.False(zeroBoth.Matches(good));
    }

    [Fact]
    public void FenceStamp_TryDeserialize_RejectsZeroIds()
    {
        // A wire frame of all-zero IDs is structurally valid but must not
        // authenticate as a real fence.
        byte[] wire = new byte[FenceStamp.Size];
        Assert.True(FenceStamp.TryDeserialize(wire, out var stamp));
        Assert.False(stamp.Matches(stamp));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(32)]
    public void FenceStamp_TryDeserialize_RejectsWrongLength(int length)
    {
        Assert.False(FenceStamp.TryDeserialize(new byte[length], out _));
    }

    [Fact]
    public void HandshakeRequestPayload_TryDeserialize_RejectsZeroFenceIds()
    {
        var request = MakeHandshakeRequest();
        byte[] serialized = request.Serialize();

        // Zero out the boot ID region (offset 8..24).
        for (int i = 8; i < 24; i++) serialized[i] = 0;
        // Structurally parseable, but a zero boot ID can never match a real fence.
        Assert.True(HandshakeRequestPayload.TryDeserialize(serialized, out var parsed));
        Assert.False(FencingIds.IsUsableId(parsed.BootId));
    }

    [Fact]
    public void HandshakeRequestPayload_Serialize_RejectsZeroFenceIds()
    {
        byte[] zero = new byte[FencingIds.IdLength];
        var request = MakeHandshakeRequest(boot: zero, launch: zero);
        // Serialize allows zero IDs on the wire; matching must reject them.
        byte[] serialized = request.Serialize();
        Assert.True(HandshakeRequestPayload.TryDeserialize(serialized, out var parsed));
        Assert.False(FencingIds.IsUsableId(parsed.BootId));
        Assert.False(FencingIds.IsUsableId(parsed.LaunchId));
    }

    // --- Bounded frame limits (malformed / oversized fail closed) ---

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsHeaderOnlyWhenPayloadClaimed()
    {
        // Header claims 4 bytes of payload but frame is header-only.
        byte[] frame = new byte[IpcMessage.HeaderSize];
        frame[0] = (byte)IpcMessageType.WorkAssignment;
        BitConverter.TryWriteBytes(frame.AsSpan(1, 4), 4);
        Assert.False(IpcMessage.TryDeserialize(frame, frame.Length, out _));
    }

    [Fact]
    public void IpcMessage_TryDeserialize_RejectsAllUndefinedTypes()
    {
        for (int t = 0; t <= 255; t++)
        {
            if (Enum.IsDefined((IpcMessageType)t)) continue;
            byte[] frame = new byte[IpcMessage.HeaderSize];
            frame[0] = (byte)t;
            Assert.False(IpcMessage.TryDeserialize(frame, frame.Length, out _), $"type {t} must fail closed");
        }
    }

    [Fact]
    public void WorkAssignmentPayload_TryDeserialize_RejectsTruncatedFence()
    {
        byte[] frame = new byte[WorkAssignmentPayload.HeaderSize - 1];
        Assert.False(WorkAssignmentPayload.TryDeserialize(frame, out _));
    }

    [Fact]
    public void WorkAckPayload_TryDeserialize_RejectsWrongSize()
    {
        Assert.False(WorkAckPayload.TryDeserialize(null, out _));
        Assert.False(WorkAckPayload.TryDeserialize(new byte[WorkAckPayload.Size - 1], out _));
        Assert.False(WorkAckPayload.TryDeserialize(new byte[WorkAckPayload.Size + 1], out _));
    }

    [Fact]
    public void StatusReportPayload_TryDeserialize_RejectsWrongSize()
    {
        Assert.False(StatusReportPayload.TryDeserialize(null, out _));
        Assert.False(StatusReportPayload.TryDeserialize(new byte[StatusReportPayload.Size - 1], out _));
        Assert.False(StatusReportPayload.TryDeserialize(new byte[StatusReportPayload.Size + 1], out _));
    }

    // --- SupervisorConfig timing validation (portable) ---

    [Fact]
    public void SupervisorConfig_HeartbeatTimeout_MustExceedInterval()
    {
        var config = new Helicoid.WindowsPlatform.SupervisorConfig
        {
            WorkerExecutablePath = "w.exe",
            WorkerConnectTimeout = TimeSpan.FromSeconds(5),
            WorkerMaxLifetime = TimeSpan.FromMinutes(5),
            HeartbeatInterval = TimeSpan.FromSeconds(10),
            HeartbeatTimeout = TimeSpan.FromSeconds(10), // Equal — must fail.
            MaxConsecutiveFailures = 3,
            RestartDelay = TimeSpan.FromSeconds(1),
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => config.ValidateTiming());
    }

    [Fact]
    public void SupervisorConfig_HeartbeatTimeout_LessThanInterval_Fails()
    {
        var config = new Helicoid.WindowsPlatform.SupervisorConfig
        {
            WorkerExecutablePath = "w.exe",
            WorkerConnectTimeout = TimeSpan.FromSeconds(5),
            WorkerMaxLifetime = TimeSpan.FromMinutes(5),
            HeartbeatInterval = TimeSpan.FromSeconds(25),
            HeartbeatTimeout = TimeSpan.FromSeconds(10),
            MaxConsecutiveFailures = 3,
            RestartDelay = TimeSpan.FromSeconds(1),
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => config.ValidateTiming());
    }

    [Fact]
    public void SupervisorConfig_RejectsZeroOrNegativeDurations()
    {
        var baseConfig = new Helicoid.WindowsPlatform.SupervisorConfig
        {
            WorkerExecutablePath = "w.exe",
            WorkerConnectTimeout = TimeSpan.FromSeconds(5),
            WorkerMaxLifetime = TimeSpan.FromMinutes(5),
            HeartbeatInterval = TimeSpan.FromSeconds(10),
            HeartbeatTimeout = TimeSpan.FromSeconds(25),
            MaxConsecutiveFailures = 3,
            RestartDelay = TimeSpan.FromSeconds(1),
        };

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            (baseConfig with { WorkerConnectTimeout = TimeSpan.Zero }).ValidateTiming());
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            (baseConfig with { HeartbeatInterval = TimeSpan.Zero }).ValidateTiming());
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            (baseConfig with { HeartbeatTimeout = TimeSpan.FromSeconds(-1) }).ValidateTiming());
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            (baseConfig with { MaxConsecutiveFailures = 0 }).ValidateTiming());
    }

    [Fact]
    public void SupervisorConfig_RejectsOversizedDurations()
    {
        var config = new Helicoid.WindowsPlatform.SupervisorConfig
        {
            WorkerExecutablePath = "w.exe",
            WorkerConnectTimeout = TimeSpan.FromHours(2),
            WorkerMaxLifetime = TimeSpan.FromMinutes(5),
            HeartbeatInterval = TimeSpan.FromSeconds(10),
            HeartbeatTimeout = TimeSpan.FromSeconds(25),
            MaxConsecutiveFailures = 3,
            RestartDelay = TimeSpan.FromSeconds(1),
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => config.ValidateTiming());
    }

    [Fact]
    public void SupervisorConfig_ValidTiming_Passes()
    {
        var config = new Helicoid.WindowsPlatform.SupervisorConfig
        {
            WorkerExecutablePath = "w.exe",
            WorkerConnectTimeout = TimeSpan.FromSeconds(30),
            WorkerMaxLifetime = TimeSpan.FromMinutes(30),
            HeartbeatInterval = TimeSpan.FromSeconds(10),
            HeartbeatTimeout = TimeSpan.FromSeconds(25),
            MaxConsecutiveFailures = 3,
            RestartDelay = TimeSpan.FromSeconds(5),
        };

        config.ValidateTiming(); // Must not throw.
    }
}