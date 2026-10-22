using System.Security.Cryptography;
using System.Text.Json;
using Helicoid.Domain.Client;

namespace Helicoid.WindowsPlatform;

/// <summary>Runs one grant-bound answer, channel-proof, and short capture lease.</summary>
internal static class EndpointObservationSession
{
    private const uint PeerStateChannelOpen = 2;
    private const uint PeerStateClosing = 3;
    private const uint PeerStateClosed = 4;
    private const uint PeerStateFailed = 5;
    private const int MaximumProofBytes = 4096;

    public static async Task<ObservationAdmissionChallenge> RunAsync(
        EndpointFileDeliveryClient client,
        string grantToken,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantToken);

        using var peer = EndpointNativeWebRtcPeer.CreateSendOnly();
        byte[] localCertificate = peer.ExportLocalCertificatePem();
        ObservationAdmissionChallenge challenge;
        try
        {
            challenge = await client.PrepareObservationAdmissionAsync(
                grantToken, localCertificate, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(localCertificate);
        }

        EndpointObservationAdmission? admission = null;
        bool challengePublished = false;
        bool managerClosed = false;
        try
        {
            await client.PublishObservationSignalAsync(
                challenge.Id,
                ObservationSignalKind.Challenge,
                System.Text.Json.JsonSerializer.Serialize(new
                {
                    computer_id = challenge.ComputerId,
                    endpoint_session_id = challenge.EndpointSessionId,
                    endpoint_nonce = challenge.EndpointNonceHex,
                    expires_at_unix = challenge.ExpiresAtUnix,
                    endpoint_certificate_pem = challenge.EndpointCertificatePem,
                    endpoint_certificate_signature = challenge.EndpointCertificateSignatureHex,
                }),
                cancellationToken).ConfigureAwait(false);
            challengePublished = true;

            admission = await NegotiateAndStreamAsync(
                client,
                peer,
                challenge,
                cancellationToken,
                onManagerClose: () => managerClosed = true,
                onAdmission: value => admission = value).ConfigureAwait(false);
            return challenge;
        }
        finally
        {
            if (challengePublished && !managerClosed)
            {
                using var closeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                try
                {
                    await client.PublishObservationSignalAsync(
                        challenge.Id,
                        ObservationSignalKind.Close,
                        string.Empty,
                        closeTimeout.Token).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Try the authenticated close even when the session token
                    // was cancelled. Grant expiry and native teardown remain
                    // the fallback if the client or physical-console session
                    // is no longer available.
                }
            }
            if (admission is not null)
            {
                client.EndObservationAdmission(admission);
            }
            peer.EndObservation();
            peer.Dispose();
            client.ForgetObservationChallenge(challenge.Id);
        }
    }

    private static async Task<EndpointObservationAdmission> NegotiateAndStreamAsync(
        EndpointFileDeliveryClient client,
        EndpointNativeWebRtcPeer peer,
        ObservationAdmissionChallenge challenge,
        CancellationToken cancellationToken,
        Action onManagerClose,
        Action<EndpointObservationAdmission> onAdmission)
    {
        ulong cursor = 1;
        bool offerAccepted = false;
        bool answerPublished = false;
        var queuedIce = new List<string>(16);
        EndpointObservationAdmission? admission = null;
        bool captureStarted = false;
        try
        {
            while (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < challenge.ExpiresAtUnix)
            {
                cancellationToken.ThrowIfCancellationRequested();
                uint state = peer.State();
                if (state is PeerStateClosing or PeerStateClosed or PeerStateFailed)
                {
                    throw InvalidObservationState("The Manager's WebRTC peer closed before the grant ended.");
                }

                while (peer.TryPollLocalIceCandidate(out string candidate))
                {
                    await client.PublishObservationSignalAsync(
                        challenge.Id,
                        ObservationSignalKind.Ice,
                        candidate,
                        cancellationToken).ConfigureAwait(false);
                }

                ObservationSignalBatch batch = await client.PollObservationSignalsAsync(
                    challenge.Id, cursor, cancellationToken).ConfigureAwait(false);
                cursor = batch.Cursor;
                foreach (ObservationSignalMessage message in batch.Messages)
                {
                    if (message.Kind == "close")
                    {
                        onManagerClose();
                        return admission ?? throw InvalidObservationState(
                            "The Manager closed before endpoint admission completed.");
                    }

                    if (message.Kind == "offer")
                    {
                        if (offerAccepted || answerPublished)
                        {
                            throw InvalidObservationState("The Manager sent more than one SDP offer.");
                        }

                        string cleanOffer = client.VerifyManagerObservationOffer(
                            challenge.Id,
                            message.Payload,
                            out byte[] managerCertificate);
                        try
                        {
                            peer.SetExpectedManagerCertificate(managerCertificate);
                            peer.SetRemoteOffer(cleanOffer);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(managerCertificate);
                        }

                        offerAccepted = true;
                        foreach (string queuedCandidate in queuedIce)
                        {
                            peer.AddRemoteIceCandidate(queuedCandidate);
                        }
                        queuedIce.Clear();
                        string answer = peer.CreateAnswer();
                        await client.PublishObservationSignalAsync(
                            challenge.Id,
                            ObservationSignalKind.Answer,
                            answer,
                            cancellationToken).ConfigureAwait(false);
                        answerPublished = true;
                    }
                    else if (message.Kind == "ice")
                    {
                        if (offerAccepted)
                        {
                            peer.AddRemoteIceCandidate(message.Payload);
                        }
                        else
                        {
                            if (queuedIce.Count >= 16)
                            {
                                throw InvalidObservationState("The pre-offer ICE queue exceeded its bound.");
                            }
                            queuedIce.Add(message.Payload);
                        }
                    }
                    else
                    {
                        throw InvalidObservationState("The Manager sent an unsupported signaling value.");
                    }
                }

                state = peer.State();
                if (state is PeerStateClosing or PeerStateClosed or PeerStateFailed)
                {
                    throw InvalidObservationState("The verified WebRTC peer closed or failed.");
                }

                if (answerPublished && state == PeerStateChannelOpen)
                {
                    while (peer.TryPollProductMessage(out byte[] proofMessage))
                    {
                        try
                        {
                            ParsedAdmissionProof proof = ParseAdmissionProof(proofMessage);
                            if (!string.Equals(proof.GrantId, challenge.GrantId, StringComparison.Ordinal) ||
                                !string.Equals(proof.EndpointNonce, challenge.EndpointNonceHex, StringComparison.Ordinal))
                            {
                                throw InvalidObservationState("The Manager proof did not match this grant and nonce.");
                            }

                            byte[] currentBinding = peer.ExportVerifiedChannelBinding();
                            try
                            {
                                string currentBindingHex = ObservationAdmissionGrantVerifier.CanonicalChannelBindingHex(
                                    currentBinding) ?? throw InvalidObservationState(
                                        "The native DTLS channel binding was invalid.");
                                if (!string.Equals(currentBindingHex, proof.ChannelBinding, StringComparison.Ordinal))
                                {
                                    throw InvalidObservationState("The Manager proof named another DTLS channel.");
                                }

                                admission = await client.RedeemObservationAdmissionAsync(
                                    challenge.Id,
                                    proof.ManagerProof,
                                    peer.ExportVerifiedChannelBinding,
                                    cancellationToken).ConfigureAwait(false);
                                onAdmission(admission);
                                uint remainingMs = admission.RemainingMilliseconds;
                                if (remainingMs == 0 || !admission.IsCurrent)
                                {
                                    throw InvalidObservationState("The server-redeemed observation lease expired.");
                                }
                                peer.BeginObservation(currentBinding, remainingMs);
                                peer.BeginCapture();
                                captureStarted = true;
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(currentBinding);
                            }
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(proofMessage);
                        }
                        break;
                    }
                }

                if (admission is not null)
                {
                    if (!captureStarted || !admission.IsCurrent || peer.State() != PeerStateChannelOpen)
                    {
                        break;
                    }

                    using CapturedObservationFrame? frame = await client.CaptureAdmittedFrameAsync(
                        admission,
                        cancellationToken).ConfigureAwait(false);
                    if (frame is not null && admission.IsCurrent)
                    {
                        peer.PushScreenFrame(frame.Pixels, frame.Width, frame.Height, frame.Stride);
                    }
                    else if (!PhysicalConsoleObserver.Observe().IsEligible || !admission.IsCurrent)
                    {
                        break;
                    }
                }

                await Task.Delay(
                    admission is null ? TimeSpan.FromMilliseconds(100) : TimeSpan.FromMilliseconds(200),
                    cancellationToken).ConfigureAwait(false);
            }

            if (admission is null)
            {
                throw InvalidObservationState("The endpoint grant expired before a verified channel was admitted.");
            }
            return admission;
        }
        finally
        {
            if (captureStarted)
            {
                peer.EndObservation();
            }
        }
    }

    private static ParsedAdmissionProof ParseAdmissionProof(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumProofBytes)
        {
            throw InvalidObservationState("The Manager admission proof exceeded its bound.");
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                MaxDepth = 2,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw InvalidObservationState("The Manager admission proof was not an object.");
            }

            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String ||
                    !values.TryAdd(property.Name, property.Value.GetString() ?? string.Empty))
                {
                    throw InvalidObservationState("The Manager admission proof contained invalid fields.");
                }
            }

            if (values.Count != 5 ||
                !values.TryGetValue("type", out string? type) || type != "observation_admission_proof" ||
                !values.TryGetValue("grant_id", out string? grantId) ||
                !values.TryGetValue("endpoint_nonce", out string? nonce) ||
                !values.TryGetValue("channel_binding", out string? binding) ||
                !values.TryGetValue("manager_proof", out string? proof) ||
                !IsLowerHex(nonce, 32) || !IsLowerHex(binding, minBytes: 16, maxBytes: 128) ||
                !IsLowerHex(proof, 64))
            {
                throw InvalidObservationState("The Manager admission proof was malformed.");
            }

            return new ParsedAdmissionProof(grantId, nonce, binding, proof);
        }
        catch (JsonException exception)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "The Manager admission proof was invalid JSON.",
                exception);
        }
    }

    private static bool IsLowerHex(string? value, int bytes) =>
        IsLowerHex(value, bytes, bytes);

    private static bool IsLowerHex(string? value, int minBytes, int maxBytes) =>
        value is not null && value.Length >= minBytes * 2 && value.Length <= maxBytes * 2 &&
        value.Length % 2 == 0 && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static ServerClientException InvalidObservationState(string message) => new(
        ServerClientFailure.InvalidResponse,
        message);

    private sealed record ParsedAdmissionProof(
        string GrantId,
        string EndpointNonce,
        string ChannelBinding,
        string ManagerProof);
}
