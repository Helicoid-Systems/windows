using System.Security.Cryptography;
using Helicoid.Domain.Client;
using Helicoid.WebRtc;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Owned Windows endpoint bridge handles for one observation negotiation.
/// This type exposes no capture authority; callers must verify and redeem a
/// current server grant before calling BeginObservation or CaptureBegin.
/// </summary>
internal sealed class EndpointNativeWebRtcPeer : IDisposable
{
    private const uint StatusOk = 0;
    private const uint StatusTimeout = 9;
    private const uint StatusExhausted = 5;
    private const uint RequiredAbiVersion = 3;
    private const uint RequiredObservationCapabilities = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40;
    private const uint VideoRoleSendOnly = 1;
    private const int MaximumCertificateBytes = 8192;
    private const int MaximumSdpBytes = 65_536;
    private const int MaximumBindingBytes = 128;

    private IntPtr _engine;
    private IntPtr _peer;
    private bool _disposed;

    private EndpointNativeWebRtcPeer(IntPtr engine, IntPtr peer, uint generation)
    {
        _engine = engine;
        _peer = peer;
        Generation = generation;
    }

    public uint Generation { get; }

    public static void EnsureObservationAvailable()
    {
        try
        {
            if (HsWebRtcNative.hs_abi_version() != RequiredAbiVersion)
            {
                throw NativeFailure("The bundled WebRTC bridge ABI is incompatible with this endpoint.");
            }
            RequireSuccess(HsWebRtcNative.hs_engine_capabilities(out uint capabilities), "query capabilities");
            if ((capabilities & RequiredObservationCapabilities) != RequiredObservationCapabilities)
            {
                throw NativeFailure("The bundled WebRTC bridge has not enabled endpoint observation.");
            }
        }
        catch (DllNotFoundException)
        {
            throw NativeFailure("The native WebRTC bridge is not bundled with this endpoint build.");
        }
        catch (EntryPointNotFoundException)
        {
            throw NativeFailure("The bundled WebRTC bridge does not expose the required endpoint ABI.");
        }
        catch (BadImageFormatException)
        {
            throw NativeFailure("The bundled WebRTC bridge architecture does not match this endpoint.");
        }
    }

    public static EndpointNativeWebRtcPeer CreateSendOnly()
    {
        EnsureObservationAvailable();
        try
        {
            return CreateSendOnlyCore();
        }
        catch (DllNotFoundException)
        {
            throw NativeFailure("The native WebRTC bridge is not bundled with this endpoint build.");
        }
        catch (EntryPointNotFoundException)
        {
            throw NativeFailure("The bundled WebRTC bridge does not expose the required endpoint ABI.");
        }
        catch (BadImageFormatException)
        {
            throw NativeFailure("The bundled WebRTC bridge architecture does not match this endpoint.");
        }
    }

    private static EndpointNativeWebRtcPeer CreateSendOnlyCore()
    {
        RequireSuccess(HsWebRtcNative.hs_engine_init(out IntPtr engine), "initialize engine");
        if (engine == IntPtr.Zero)
        {
            throw NativeFailure("The bundled WebRTC bridge returned an empty engine handle.");
        }

        IntPtr peer = IntPtr.Zero;
        try
        {
            RequireSuccess(HsWebRtcNative.hs_peer_create(engine, out peer), "create peer");
            if (peer == IntPtr.Zero)
            {
                throw NativeFailure("The bundled WebRTC bridge returned an empty peer handle.");
            }
            RequireSuccess(HsWebRtcNative.hs_peer_video_prepare(peer, VideoRoleSendOnly), "prepare video");
            // The Manager creates the hs-product channel in its offer. The
            // endpoint is the answerer and accepts only that negotiated channel.
            RequireSuccess(HsWebRtcNative.hs_peer_generation(peer, out uint generation), "read generation");
            if (generation == 0)
            {
                throw NativeFailure("The WebRTC peer generation is invalid.");
            }
            return new EndpointNativeWebRtcPeer(engine, peer, generation);
        }
        catch
        {
            if (peer != IntPtr.Zero)
            {
                _ = HsWebRtcNative.hs_peer_drain(peer, 5_000);
            }
            _ = HsWebRtcNative.hs_engine_shutdown(engine);
            throw;
        }
    }

    public byte[] ExportLocalCertificatePem()
    {
        EnsureOpen();
        byte[] buffer = new byte[MaximumCertificateBytes];
        try
        {
            RequireSuccess(HsWebRtcNative.hs_peer_local_cert_export(
                _peer, buffer, (uint)buffer.Length, out uint length), "export local certificate");
            if (length == 0 || length > buffer.Length ||
                Array.IndexOf(buffer, (byte)0, 0, checked((int)length)) >= 0)
            {
                throw NativeFailure("The native certificate export exceeded its bounds.");
            }
            return buffer.AsSpan(0, checked((int)length)).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public void SetExpectedManagerCertificate(ReadOnlySpan<byte> certificatePem)
    {
        EnsureOpen();
        if (certificatePem.IsEmpty || certificatePem.Length > MaximumCertificateBytes)
        {
            throw NativeFailure("The Manager certificate exceeds its native bounds.");
        }
        byte[] bytes = certificatePem.ToArray();
        try
        {
            RequireSuccess(HsWebRtcNative.hs_peer_expected_cert_set(
                _peer, bytes, (UIntPtr)(uint)bytes.Length), "pin Manager certificate");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void SetRemoteOffer(string offerSdp)
    {
        EnsureSdp(offerSdp);
        byte[] type = "offer"u8.ToArray();
        byte[] sdp = System.Text.Encoding.ASCII.GetBytes(offerSdp);
        try
        {
            RequireSuccess(HsWebRtcNative.hs_peer_set_remote(
                _peer, type, (UIntPtr)(uint)type.Length, sdp, (UIntPtr)(uint)sdp.Length),
                "set remote offer");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(type);
            CryptographicOperations.ZeroMemory(sdp);
        }
    }

    public string CreateAnswer()
    {
        EnsureOpen();
        byte[] buffer = new byte[MaximumSdpBytes + 1];
        try
        {
            RequireSuccess(HsWebRtcNative.hs_peer_create_answer(
                _peer, buffer, (UIntPtr)(uint)buffer.Length, out UIntPtr rawLength), "create answer");
            ulong length = rawLength.ToUInt64();
            if (length == 0 || length > MaximumSdpBytes || buffer[checked((int)length)] != 0 ||
                Array.IndexOf(buffer, (byte)0, 0, checked((int)length)) >= 0)
            {
                throw NativeFailure("The native SDP answer exceeded its bounds.");
            }
            return System.Text.Encoding.ASCII.GetString(buffer, 0, checked((int)length));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public uint State()
    {
        EnsureOpen();
        RequireSuccess(HsWebRtcNative.hs_peer_state(_peer, out uint state), "read peer state");
        return state;
    }

    public byte[] ExportVerifiedChannelBinding()
    {
        EnsureOpen();
        RequireSuccess(HsWebRtcNative.hs_verified_channel_acquire(_peer, out IntPtr channel),
            "acquire verified channel");
        if (channel == IntPtr.Zero)
        {
            throw NativeFailure("The native bridge returned an empty verified-channel handle.");
        }

        byte[] buffer = new byte[MaximumBindingBytes];
        try
        {
            RequireSuccess(HsWebRtcNative.hs_verified_channel_binding_export(
                channel, buffer, (uint)buffer.Length, out uint length), "export channel binding");
            if (length == 0 || length > buffer.Length)
            {
                throw NativeFailure("The native channel binding exceeded its bounds.");
            }
            return buffer.AsSpan(0, checked((int)length)).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            RequireSuccess(HsWebRtcNative.hs_verified_channel_release(channel), "release verified channel");
        }
    }

    public void BeginObservation(ReadOnlySpan<byte> channelBinding, uint leaseMs)
    {
        EnsureOpen();
        if (channelBinding.IsEmpty || channelBinding.Length > MaximumBindingBytes || leaseMs == 0)
        {
            throw NativeFailure("The observation channel binding or lease is invalid.");
        }
        byte[] bytes = channelBinding.ToArray();
        try
        {
            RequireSuccess(HsWebRtcNative.hs_admission_begin(
                _peer, bytes, (uint)bytes.Length, leaseMs), "begin observation lease");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void BeginCapture()
    {
        EnsureOpen();
        RequireSuccess(HsWebRtcNative.hs_capture_begin(_peer, Generation), "begin capture");
    }

    public void PushScreenFrame(ReadOnlySpan<byte> bgra, uint width, uint height, uint stride)
    {
        EnsureOpen();
        if (bgra.IsEmpty || bgra.Length > 1280 * 720 * 4 || width == 0 || width > 1280 ||
            height == 0 || height > 720 || stride < width * 4 || (ulong)stride * height != (ulong)bgra.Length)
        {
            throw NativeFailure("The captured frame exceeded the native media bounds.");
        }
        byte[] bytes = bgra.ToArray();
        try
        {
            RequireSuccess(HsWebRtcNative.hs_peer_video_frame_push(
                _peer, bytes, (uint)bytes.Length, width, height, stride), "push screen frame");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void AddRemoteIceCandidate(string candidate)
    {
        EnsureOpen();
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Length > 4_096 ||
            candidate.Any(static character => character > 0x7f || character == '\0'))
        {
            throw NativeFailure("The endpoint received an invalid ICE candidate.");
        }
        byte[] bytes = System.Text.Encoding.ASCII.GetBytes(candidate);
        try
        {
            RequireSuccess(HsWebRtcNative.hs_peer_add_ice(
                _peer, bytes, (UIntPtr)(uint)bytes.Length), "add remote ICE candidate");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public bool TryPollLocalIceCandidate(out string candidate)
    {
        EnsureOpen();
        byte[] buffer = new byte[4_097];
        try
        {
            uint status = HsWebRtcNative.hs_peer_poll_ice(
                _peer, buffer, (UIntPtr)(uint)buffer.Length, out UIntPtr rawLength);
            if (status is StatusTimeout or StatusExhausted)
            {
                candidate = string.Empty;
                return false;
            }
            RequireSuccess(status, "poll local ICE candidate");
            ulong length = rawLength.ToUInt64();
            if (length == 0 || length > 4_096 || buffer[checked((int)length)] != 0)
            {
                throw NativeFailure("The native ICE candidate exceeded its bounds.");
            }
            candidate = System.Text.Encoding.ASCII.GetString(buffer, 0, checked((int)length));
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public bool TryPollProductMessage(out byte[] message)
    {
        EnsureOpen();
        byte[] buffer = new byte[4_096];
        try
        {
            uint status = HsWebRtcNative.hs_channel_poll(
                _peer, buffer, (uint)buffer.Length, out uint length);
            if (status is StatusTimeout or StatusExhausted)
            {
                message = Array.Empty<byte>();
                return false;
            }
            RequireSuccess(status, "poll product message");
            if (length == 0 || length > buffer.Length)
            {
                throw NativeFailure("The native product message exceeded its bounds.");
            }
            message = buffer.AsSpan(0, checked((int)length)).ToArray();
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public void EndObservation()
    {
        if (_peer != IntPtr.Zero)
        {
            _ = HsWebRtcNative.hs_capture_end(_peer);
            _ = HsWebRtcNative.hs_admission_end(_peer);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        IntPtr peer = Interlocked.Exchange(ref _peer, IntPtr.Zero);
        IntPtr engine = Interlocked.Exchange(ref _engine, IntPtr.Zero);
        if (peer != IntPtr.Zero)
        {
            _ = HsWebRtcNative.hs_capture_end(peer);
            _ = HsWebRtcNative.hs_admission_end(peer);
            _ = HsWebRtcNative.hs_channel_close(peer);
            _ = HsWebRtcNative.hs_peer_close(peer);
            uint drain = HsWebRtcNative.hs_peer_drain(peer, 5_000);
            if (drain != StatusOk)
            {
                _ = HsWebRtcNative.hs_engine_drain(engine, 5_000);
                drain = HsWebRtcNative.hs_peer_drain(peer, 5_000);
            }
        }
        if (engine != IntPtr.Zero)
        {
            _ = HsWebRtcNative.hs_engine_drain(engine, 5_000);
            _ = HsWebRtcNative.hs_engine_shutdown(engine);
        }
    }

    private void EnsureOpen()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_engine == IntPtr.Zero || _peer == IntPtr.Zero)
        {
            throw NativeFailure("The endpoint WebRTC peer is unavailable.");
        }
    }

    private static void EnsureSdp(string sdp)
    {
        ArgumentNullException.ThrowIfNull(sdp);
        if (sdp.Length is 0 or > MaximumSdpBytes || !sdp.StartsWith("v=0", StringComparison.Ordinal) ||
            sdp.Any(static character => character > 0x7f || character == '\0'))
        {
            throw NativeFailure("The endpoint received invalid SDP.");
        }
    }

    private static void RequireSuccess(uint status, string operation)
    {
        if (status != StatusOk)
        {
            throw NativeFailure($"Native WebRTC could not {operation} (status {status}).");
        }
    }

    private static ServerClientException NativeFailure(string message) => new(
        ServerClientFailure.NotAvailableInThisBuild,
        message);
}
