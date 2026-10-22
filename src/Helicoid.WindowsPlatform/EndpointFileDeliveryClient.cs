using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Helicoid.Domain.Client;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform.Native;

namespace Helicoid.WindowsPlatform;

/// <summary>One file verified and published by this Windows endpoint.</summary>
public sealed record ReceivedEndpointFile(string JobId, string FileName, string Path);

/// <summary>An open file request assigned to this enrolled computer.</summary>
public sealed record EndpointFileRequest(
    string Id,
    long Revision,
    string Title,
    string Instructions,
    IReadOnlyList<string> AllowedExtensions,
    uint MaxFileCount,
    ulong MaxTotalSizeBytes,
    long ClosesAtUnix,
    bool ReplacementAllowed);

/// <summary>A file in one endpoint file-request submission.</summary>
public sealed record EndpointFileRequestSubmissionFile(
    string Id,
    string FileName,
    ulong FileSizeBytes,
    string Sha256,
    string State);

/// <summary>Submission history visible to its exact endpoint and local user.</summary>
public sealed record EndpointFileRequestSubmission(
    string Id,
    string RequestId,
    long RequestRevision,
    string ComputerId,
    string LocalUserDisplayName,
    string State,
    long CreatedAtUnix,
    IReadOnlyList<EndpointFileRequestSubmissionFile> Files);

/// <summary>Fresh endpoint nonce awaiting the Manager's signed peer proof.</summary>
public sealed record ObservationAdmissionChallenge(
    Guid Id,
    string GrantId,
    string ComputerId,
    string EndpointSessionId,
    string EndpointNonceHex,
    long ExpiresAtUnix,
    string? EndpointCertificatePem = null,
    string? EndpointCertificateSignatureHex = null);

public enum ObservationSignalKind
{
    Challenge,
    Offer,
    Answer,
    Ice,
    Close,
}

public sealed record ObservationSignalMessage(
    [property: JsonPropertyName("sequence")] ulong Sequence,
    [property: JsonPropertyName("sender")] string Sender,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("payload")] string Payload);

public sealed record ObservationSignalBatch(
    [property: JsonPropertyName("cursor")] ulong Cursor,
    [property: JsonPropertyName("messages")] IReadOnlyList<ObservationSignalMessage> Messages);

/// <summary>File delivery paused because no eligible console user is available.</summary>
public sealed class EndpointFileDeliveryWaitingForUserException : Exception
{
    /// <summary>Create a user-visible delivery pause.</summary>
    public EndpointFileDeliveryWaitingForUserException(string message) : base(message) { }
}

/// <summary>
/// Admits the enrolled endpoint, receives only its leased file jobs, verifies
/// the complete payload digest, and publishes into a private per-user folder.
/// </summary>
public sealed class EndpointFileDeliveryClient : IDisposable
{
    private const int ChunkSize = 256 * 1024;
    private const ulong MaxFileBytes = 128UL * 1024 * 1024;
    private const int MaxJobs = 50;
    private const int MaxRequests = 100;
    private const int MaxActiveObservationAdmissions = 8;
    private const int MaxObservationSignalsPerGrant = 128;
    private static readonly TimeSpan MaxObservationAdmissionLifetime = TimeSpan.FromSeconds(10);
    private const int MaxResponseBytes = 4 * 1024 * 1024;
    private const string JobsPath = "/v2/endpoints/jobs";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly DeploymentTlsTrust _trust;
    private readonly PinnedHttpsTransport _transport;
    private readonly WorkerSupervisor? _observationWorker;
    private readonly string? _grantVerificationPublicKeyHex;
    private readonly long? _authorityGeneration;
    private readonly ConcurrentDictionary<Guid, PendingObservationAdmission> _pendingObservationAdmissions = new();
    private readonly ConcurrentDictionary<Guid, ActiveObservationSignalContext> _activeObservationSignals = new();
    private readonly ConcurrentDictionary<string, long> _observationGrantExpirations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, EndpointObservationAdmission> _activeObservationAdmissions = new(StringComparer.Ordinal);
    private readonly object _observationAdmissionsLock = new();
    private EndpointSession? _currentSession;
    private string? _currentSessionLocalUserId;
    private readonly SemaphoreSlim _pollGate = new(1, 1);
    private readonly SemaphoreSlim _requestGate = new(1, 1);
    private readonly SemaphoreSlim _sessionGate = new(1, 1);
    private readonly string _storageDirectory = EndpointEnrollmentClient.GetStorageDirectory();
    private volatile bool _disposed;

    /// <summary>Create a receiver pinned to the enrolled deployment trust.</summary>
    public EndpointFileDeliveryClient(DeploymentTlsTrust trust)
        : this(trust, grantVerificationPublicKeyHex: null)
    {
    }

    /// <summary>Create a receiver and grant verifier from protected enrollment state.</summary>
    public EndpointFileDeliveryClient(
        EndpointEnrollmentConfiguration configuration,
        WorkerSupervisor? observationWorker = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        _trust = configuration.Trust;
        _grantVerificationPublicKeyHex = configuration.GrantVerificationPublicKeyHex;
        _authorityGeneration = configuration.AuthorityGeneration;
        _observationWorker = observationWorker;
        _transport = new PinnedHttpsTransport(_trust, maxBodyBytes: MaxResponseBytes);
    }

    /// <summary>
    /// Wait for grants queued to this exact enrolled endpoint session, verify
    /// each one, negotiate its pinned native peer, redeem the Manager proof,
    /// and stream only during the short server-authorized lease.
    /// </summary>
    public async Task<IReadOnlyList<ObservationAdmissionChallenge>> WaitAndServeObservationGrantsAsync(
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrEmpty(_grantVerificationPublicKeyHex) ||
            !IsCanonicalLowerHex(_grantVerificationPublicKeyHex, 32))
        {
            throw new ServerClientException(
                ServerClientFailure.SecurityStateUnavailable,
                "This endpoint has no pinned observation-grant key. A trusted enrollment is required.");
        }

        // Do not consume short-lived server grants unless this packaged build
        // has the native media path needed to complete their admission.
        EndpointNativeWebRtcPeer.EnsureObservationAvailable();
        if (!PhysicalConsoleObserver.Observe().IsEligible)
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "Waiting for an unlocked physical-console desktop.");
        }
        WorkerSupervisor? observationWorker = _observationWorker;
        bool workerReady = observationWorker is not null &&
            (observationWorker.WorkerStatus == WorkerStatus.Connected ||
             await Task.Run(observationWorker.TryStartWorker, cancellationToken).ConfigureAwait(false));
        if (!workerReady)
        {
            throw new ServerClientException(
                ServerClientFailure.NotAvailableInThisBuild,
                "The per-user capture worker is unavailable.");
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (!PhysicalConsoleObserver.Observe().IsEligible)
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "Waiting for an unlocked physical-console desktop.");
        }
        await EnsureObservationEnabledAsync(cancellationToken).ConfigureAwait(false);

        var configuration = ReadMatchingEnrollmentConfiguration();
        var localUserId = GetCurrentEligibleLocalUserId()
            ?? throw new EndpointFileDeliveryWaitingForUserException(
                "Waiting for an eligible signed-in physical-console user.");
        using var keyStorage = new DeviceKeyStorage(_storageDirectory);
        var result = keyStorage.Open(out var seed, out var storedPublicKey);
        try
        {
            if (result != DeviceKeyStorageResult.Success ||
                seed.Length != Ed25519DeviceKey.SeedLength ||
                storedPublicKey.Length != Ed25519DeviceKey.PublicKeyLength)
            {
                throw StorageFailure("The protected endpoint identity could not be opened.");
            }

            using var signingKey = Ed25519DeviceKey.ImportSeed(seed);
            var publicKeyMatches = Ed25519DeviceKey.TryParsePublicKey(
                signingKey.PublicKeyHex,
                out var derivedPublicKey);
            try
            {
                if (!publicKeyMatches || derivedPublicKey.Length != storedPublicKey.Length ||
                    !CryptographicOperations.FixedTimeEquals(derivedPublicKey, storedPublicKey))
                {
                    throw StorageFailure("The protected endpoint identity is inconsistent.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedPublicKey);
            }

            var enrollment = configuration.Enrollment;
            RequireSameLocalUser(localUserId);
            var session = await CurrentEndpointSessionAsync(
                enrollment,
                localUserId,
                Environment.UserName,
                signingKey,
                cancellationToken).ConfigureAwait(false);
            signingKey.Dispose();
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(storedPublicKey);
            var response = await _transport.SendAsync(
                HttpMethod.Get,
                "/v2/endpoints/admissions/observation/pending",
                content: null,
                cancellationToken,
                session.Token,
                expectedStatusCode: 200).ConfigureAwait(false);
            try
            {
                var pending = JsonSerializer.Deserialize<EndpointPendingObservationGrants>(
                    response,
                    JsonOptions) ?? throw InvalidResponse(
                        "The observation-grant delivery response was empty.");
                if (pending.Grants is null || pending.Grants.Count > MaxActiveObservationAdmissions)
                {
                    throw InvalidResponse("The observation-grant delivery response exceeded its bound.");
                }
                if (pending.Grants.Count == 0)
                {
                    return Array.Empty<ObservationAdmissionChallenge>();
                }

                var seenGrantIds = new HashSet<string>(StringComparer.Ordinal);
                foreach (var grant in pending.Grants)
                {
                    if (grant is null || grant.ComputerId != enrollment.ComputerId ||
                        !IsCanonicalUuid(grant.GrantId) || !seenGrantIds.Add(grant.GrantId) ||
                        grant.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() ||
                        string.IsNullOrEmpty(grant.GrantToken))
                    {
                        throw InvalidResponse("The delivered observation grant did not match this endpoint.");
                    }
                }

                Task<ObservationAdmissionChallenge>[] sessions = pending.Grants.Select(grant =>
                    EndpointObservationSession.RunAsync(
                        this,
                        grant.GrantToken,
                        cancellationToken)).ToArray();
                return await Task.WhenAll(sessions).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(response);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(storedPublicKey);
        }
    }

    /// <summary>Forget an unredeemed pending challenge after its native peer ends.</summary>
    internal void ForgetObservationChallenge(Guid challengeId)
    {
        if (_pendingObservationAdmissions.TryRemove(challengeId, out var pending))
        {
            _observationGrantExpirations.TryRemove(pending.Grant.GrantId, out _);
        }
    }

    internal async Task<CapturedObservationFrame?> CaptureAdmittedFrameAsync(
        EndpointObservationAdmission admission,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(admission);
        if (!admission.IsCurrent || _observationWorker is null)
        {
            return null;
        }

        CapturedObservationFrame? frame = await _observationWorker
            .CapturePrimaryDisplayAsync(cancellationToken)
            .ConfigureAwait(false);
        if (frame is not null && !admission.IsCurrent)
        {
            frame.Dispose();
            return null;
        }
        return frame;
    }

    private EndpointFileDeliveryClient(DeploymentTlsTrust trust, string? grantVerificationPublicKeyHex)
    {
        ArgumentNullException.ThrowIfNull(trust);
        _trust = trust;
        _grantVerificationPublicKeyHex = grantVerificationPublicKeyHex;
        _transport = new PinnedHttpsTransport(trust, maxBodyBytes: MaxResponseBytes);
    }

    /// <summary>
    /// Verify a grant and attest the exact local DTLS certificate before the
    /// endpoint publishes its challenge. Callers must create the native peer
    /// first and pass its exported certificate bytes.
    /// </summary>
    public async Task<ObservationAdmissionChallenge> PrepareObservationAdmissionAsync(
        string grantToken,
        byte[] endpointCertificatePem,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpointCertificatePem);
        byte[] certificateCopy = endpointCertificatePem.ToArray();
        try
        {
            return await PrepareObservationAdmissionCoreAsync(
                grantToken,
                certificateCopy,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(certificateCopy);
        }
    }

    private async Task<ObservationAdmissionChallenge> PrepareObservationAdmissionCoreAsync(
        string grantToken,
        byte[] endpointCertificatePem,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrEmpty(_grantVerificationPublicKeyHex) ||
            !IsCanonicalLowerHex(_grantVerificationPublicKeyHex, 32))
        {
            throw new ServerClientException(
                ServerClientFailure.SecurityStateUnavailable,
                "This endpoint has no pinned observation-grant key. A trusted enrollment is required.");
        }
        if (grantToken.Length > 8 * 1024 || grantToken.Any(static character => character > 0x7f))
        {
            throw InvalidObservationGrant();
        }

        var configuration = ReadMatchingEnrollmentConfiguration();
        using var keyStorage = new DeviceKeyStorage(_storageDirectory);
        var result = keyStorage.Open(out var seed, out var storedPublicKey);
        try
        {
            if (result != DeviceKeyStorageResult.Success ||
                seed.Length != Ed25519DeviceKey.SeedLength ||
                storedPublicKey.Length != Ed25519DeviceKey.PublicKeyLength)
            {
                throw StorageFailure("The protected endpoint identity could not be opened.");
            }

            using var signingKey = Ed25519DeviceKey.ImportSeed(seed);
            var publicKeyMatches = Ed25519DeviceKey.TryParsePublicKey(
                signingKey.PublicKeyHex,
                out var derivedPublicKey);
            try
            {
                if (!publicKeyMatches || derivedPublicKey.Length != storedPublicKey.Length ||
                    !CryptographicOperations.FixedTimeEquals(derivedPublicKey, storedPublicKey))
                {
                    throw StorageFailure("The protected endpoint identity is inconsistent.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedPublicKey);
            }

            var enrollment = configuration.Enrollment;
            var localUserId = GetCurrentEligibleLocalUserId();
            if (localUserId is null)
            {
                throw new EndpointFileDeliveryWaitingForUserException(
                    "Waiting for an eligible signed-in physical-console user.");
            }
            var session = await CurrentEndpointSessionAsync(
                enrollment,
                localUserId,
                Environment.UserName,
                signingKey,
                cancellationToken).ConfigureAwait(false);
            RequireSameLocalUser(localUserId);

            var expected = new ObservationAdmissionEndpoint(
                _trust.DeploymentId,
                enrollment.ComputerId,
                signingKey.PublicKeyHex,
                session.SessionId,
                session.EnrollmentEpoch);
            var grant = ObservationAdmissionGrantVerifier.Verify(
                grantToken,
                _grantVerificationPublicKeyHex,
                expected);

            foreach (var item in _pendingObservationAdmissions)
            {
                if (item.Value.Grant.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                {
                    _pendingObservationAdmissions.TryRemove(item.Key, out _);
                }
            }
            foreach (var item in _observationGrantExpirations)
            {
                if (item.Value <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                {
                    _observationGrantExpirations.TryRemove(item.Key, out _);
                }
            }
            if (_pendingObservationAdmissions.Count >= 8)
            {
                throw new EndpointFileDeliveryWaitingForUserException(
                    "Too many observation requests are waiting for Manager proof.");
            }
            if (!_observationGrantExpirations.TryAdd(grant.GrantId, grant.ExpiresAtUnix))
            {
                throw InvalidObservationGrant();
            }

            var endpointNonce = ObservationAdmissionGrantVerifier.CreateEndpointNonce();
            if (!ObservationAdmissionGrantVerifier.IsCertificatePem(endpointCertificatePem))
            {
                throw InvalidObservationGrant();
            }
            var attestationMessage = grant.CreatePeerCertificateAttestationMessage(
                endpointCertificatePem,
                endpointNonce,
                ObservationPeerRole.Endpoint);
            var signature = signingKey.Sign(attestationMessage);
            string endpointCertificateText;
            string endpointCertificateSignature;
            try
            {
                endpointCertificateText = Encoding.UTF8.GetString(endpointCertificatePem);
                endpointCertificateSignature = Ed25519DeviceKey.ToLowerHex(signature);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(attestationMessage);
                CryptographicOperations.ZeroMemory(signature);
            }
            var challenge = new ObservationAdmissionChallenge(
                Guid.NewGuid(),
                grant.GrantId,
                grant.ComputerId,
                grant.EndpointSessionId,
                endpointNonce,
                grant.ExpiresAtUnix,
                endpointCertificateText,
                endpointCertificateSignature);
            var pending = new PendingObservationAdmission(
                grantToken,
                grant,
                challenge,
                enrollment,
                localUserId,
                session);
            if (!_pendingObservationAdmissions.TryAdd(challenge.Id, pending))
            {
                throw new ServerClientException(
                    ServerClientFailure.Conflict,
                    "A fresh endpoint observation challenge could not be registered.");
            }
            return challenge;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(storedPublicKey);
        }
    }

    /// <summary>
    /// Send one bounded signaling value for a pending grant, or send close
    /// during its active lease. A native peer still verifies DTLS identity.
    /// </summary>
    public async Task PublishObservationSignalAsync(
        Guid challengeId,
        ObservationSignalKind kind,
        string payload,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        bool activeClose = false;
        ActiveObservationSignalContext signalContext;
        if (_pendingObservationAdmissions.TryGetValue(challengeId, out var pending))
        {
            signalContext = new ActiveObservationSignalContext(
                pending.Grant.GrantId,
                pending.Challenge.ExpiresAtUnix,
                pending.LocalUserId,
                pending.Enrollment,
                pending.Session);
        }
        else if (kind == ObservationSignalKind.Close &&
                 _activeObservationSignals.TryGetValue(challengeId, out var activeSignalContext))
        {
            signalContext = activeSignalContext;
            activeClose = true;
        }
        else
        {
            throw InvalidObservationGrant();
        }
        if (signalContext.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            throw InvalidObservationGrant();
        }
        if (activeClose &&
            (!_activeObservationAdmissions.TryGetValue(signalContext.GrantId, out var activeAdmission) ||
             !activeAdmission.IsCurrent))
        {
            throw InvalidObservationGrant();
        }
        try
        {
            RequireSameLocalUser(signalContext.LocalUserId);
        }
        catch (EndpointFileDeliveryPausedException)
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "Observation signaling stopped because the signed-in physical-console user changed.");
        }
        RequireSessionCurrent(signalContext.Session);
        await VerifySelfAsync(signalContext.Session, signalContext.Enrollment, cancellationToken).ConfigureAwait(false);
        var kindText = ObservationSignalKindText(kind);
        if (!ValidObservationSignal(kind, payload))
        {
            throw new ServerClientException(
                ServerClientFailure.BadRequest,
                "The observation signaling value is invalid or exceeds its size limit.");
        }
        var requestBody = JsonSerializer.SerializeToUtf8Bytes(
            new ObservationSignalRequest(kindText, payload),
            JsonOptions);
        try
        {
            using var content = new ByteArrayContent(requestBody);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            var response = await _transport.SendAsync(
                HttpMethod.Post,
                $"/v2/endpoints/admissions/observation/{signalContext.GrantId}/signals",
                content,
                cancellationToken,
                signalContext.Session.Token,
                expectedStatusCode: 204).ConfigureAwait(false);
            try
            {
                if (response.Length != 0)
                {
                    throw InvalidResponse("The observation signaling response was not empty.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(response);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBody);
        }
    }

    /// <summary>Poll the exact pending grant for Manager SDP/ICE values.</summary>
    public async Task<ObservationSignalBatch> PollObservationSignalsAsync(
        Guid challengeId,
        ulong after,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_pendingObservationAdmissions.TryGetValue(challengeId, out var pending) ||
            pending.Challenge.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            throw InvalidObservationGrant();
        }
        try
        {
            RequireSameLocalUser(pending.LocalUserId);
        }
        catch (EndpointFileDeliveryPausedException)
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "Observation signaling stopped because the signed-in physical-console user changed.");
        }
        RequireSessionCurrent(pending.Session);
        await VerifySelfAsync(pending.Session, pending.Enrollment, cancellationToken).ConfigureAwait(false);
        var response = await _transport.SendAsync(
            HttpMethod.Get,
            $"/v2/endpoints/admissions/observation/{pending.Grant.GrantId}/signals?after={after}",
            content: null,
            cancellationToken,
            pending.Session.Token,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            if (response.Length is 0 or > 256 * 1024)
            {
                throw InvalidResponse("The observation signaling response exceeded its bound.");
            }
            var batch = JsonSerializer.Deserialize<ObservationSignalBatch>(response, JsonOptions)
                ?? throw InvalidResponse("The observation signaling response was empty.");
            if (batch.Cursor < after || batch.Cursor > MaxObservationSignalsPerGrant ||
                batch.Messages is null || batch.Messages.Count > 64)
            {
                throw InvalidResponse("The observation signaling cursor or message count was invalid.");
            }

            ulong lastSequence = after;
            foreach (var message in batch.Messages)
            {
                if (message is null || message.Sequence <= lastSequence ||
                    message.Sequence > MaxObservationSignalsPerGrant ||
                    message.Sequence > batch.Cursor || message.Sender != "manager" ||
                    !ValidManagerObservationSignal(message.Kind, message.Payload))
                {
                    throw InvalidResponse("The observation signaling batch contained an invalid Manager message.");
                }
                lastSequence = message.Sequence;
            }
            return batch;
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The observation signaling response was invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(response);
        }
    }

    /// <summary>
    /// Verify the Manager's offer certificate for this exact challenge before
    /// passing the stripped SDP or PEM to native WebRTC.
    /// </summary>
    public string VerifyManagerObservationOffer(
        Guid challengeId,
        string offerSdp,
        out byte[] managerCertificatePem)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_pendingObservationAdmissions.TryGetValue(challengeId, out var pending) ||
            pending.Challenge.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            managerCertificatePem = Array.Empty<byte>();
            throw InvalidObservationGrant();
        }
        try
        {
            RequireSameLocalUser(pending.LocalUserId);
        }
        catch (EndpointFileDeliveryPausedException)
        {
            managerCertificatePem = Array.Empty<byte>();
            throw new EndpointFileDeliveryWaitingForUserException(
                "Observation stopped because the signed-in physical-console user changed.");
        }
        RequireSessionCurrent(pending.Session);
        return ObservationPeerOffer.RemoveAndVerifyManagerCertificateAttestation(
            offerSdp,
            pending.Grant,
            pending.Challenge.EndpointNonceHex,
            out managerCertificatePem);
    }

    /// <summary>
    /// Verify Manager proof and redeem this exact challenge once. The callback
    /// must export from the current native verified-channel handle; the
    /// returned admission rechecks that same channel binding while current.
    /// </summary>
    public async Task<EndpointObservationAdmission> RedeemObservationAdmissionAsync(
        Guid challengeId,
        string managerProofHex,
        Func<byte[]> currentVerifiedChannelBinding,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(currentVerifiedChannelBinding);
        if (!_pendingObservationAdmissions.TryRemove(challengeId, out var pending))
        {
            throw InvalidObservationGrant();
        }
        var channelBindingHex = ReadCurrentChannelBindingHex(currentVerifiedChannelBinding);
        if (pending.Challenge.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() ||
            channelBindingHex is null ||
            !pending.Grant.VerifyManagerProof(
                pending.Challenge.EndpointNonceHex,
                channelBindingHex,
                managerProofHex))
        {
            throw InvalidObservationGrant();
        }

        try
        {
            RequireSameLocalUser(pending.LocalUserId);
        }
        catch (EndpointFileDeliveryPausedException)
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "Observation stopped because the signed-in physical-console user changed.");
        }
        RequireSessionCurrent(pending.Session);
        await VerifySelfAsync(pending.Session, pending.Enrollment, cancellationToken).ConfigureAwait(false);
        if (pending.Challenge.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() ||
            !string.Equals(
                ReadCurrentChannelBindingHex(currentVerifiedChannelBinding),
                channelBindingHex,
                StringComparison.Ordinal))
        {
            throw InvalidObservationGrant();
        }

        var accepted = await PostJsonAsync<ObservationAdmissionAcceptedResponse>(
            "/v2/endpoints/admissions/observation/redeem",
            new RedeemObservationGrantRequest(
                pending.GrantToken,
                pending.Challenge.EndpointNonceHex,
                channelBindingHex,
                managerProofHex),
            expectedStatus: 200,
            bearerToken: pending.Session.Token,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (accepted.GrantId != pending.Grant.GrantId ||
            accepted.ComputerId != pending.Enrollment.ComputerId ||
            accepted.EndpointSessionId != pending.Session.SessionId ||
            accepted.ExpiresAtUnix != pending.Grant.ExpiresAtUnix)
        {
            throw InvalidResponse("The server admitted a different endpoint observation grant.");
        }
        try
        {
            RequireSameLocalUser(pending.LocalUserId);
        }
        catch (EndpointFileDeliveryPausedException)
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "Observation stopped because the signed-in physical-console user changed.");
        }
        if (!string.Equals(
                ReadCurrentChannelBindingHex(currentVerifiedChannelBinding),
                channelBindingHex,
                StringComparison.Ordinal))
        {
            throw InvalidObservationGrant();
        }
        var admissionStartedAt = Stopwatch.GetTimestamp();
        var remainingLifetime = DateTimeOffset.FromUnixTimeSeconds(accepted.ExpiresAtUnix) - DateTimeOffset.UtcNow;
        if (remainingLifetime <= TimeSpan.Zero || remainingLifetime > MaxObservationAdmissionLifetime)
        {
            throw InvalidObservationGrant();
        }

        var admission = new EndpointObservationAdmission(
            challengeId,
            accepted.GrantId,
            accepted.ComputerId,
            accepted.EndpointSessionId,
            accepted.ExpiresAtUnix,
            pending.LocalUserId,
            remainingLifetime,
            admissionStartedAt,
            channelBindingHex,
            currentVerifiedChannelBinding);
        lock (_observationAdmissionsLock)
        {
            if (_disposed)
            {
                admission.Dispose();
                throw new ObjectDisposedException(nameof(EndpointFileDeliveryClient));
            }

            foreach (var active in _activeObservationAdmissions)
            {
                if (!active.Value.IsCurrent)
                {
                    _activeObservationAdmissions.TryRemove(active.Key, out _);
                }
            }

            if (_activeObservationAdmissions.Count >= MaxActiveObservationAdmissions ||
                !_activeObservationAdmissions.TryAdd(admission.GrantId, admission))
            {
                admission.Dispose();
                throw new EndpointFileDeliveryWaitingForUserException(
                    "Too many observation sessions are already active on this endpoint.");
            }
            if (!_activeObservationSignals.TryAdd(
                    challengeId,
                    new ActiveObservationSignalContext(
                        accepted.GrantId,
                        accepted.ExpiresAtUnix,
                        pending.LocalUserId,
                        pending.Enrollment,
                        pending.Session)))
            {
                _activeObservationAdmissions.TryRemove(admission.GrantId, out _);
                admission.Dispose();
                throw new EndpointFileDeliveryWaitingForUserException(
                    "The endpoint observation signal session could not be registered.");
            }
        }
        if (!admission.IsCurrent)
        {
            EndObservationAdmission(admission);
            throw new EndpointFileDeliveryWaitingForUserException(
                "Observation stopped because the physical-console user or unlocked desktop changed.");
        }
        return admission;
    }

    /// <summary>End this exact redeemed admission and release its local lease.</summary>
    public void EndObservationAdmission(EndpointObservationAdmission admission)
    {
        ArgumentNullException.ThrowIfNull(admission);
        admission.Dispose();
        lock (_observationAdmissionsLock)
        {
            _activeObservationSignals.TryRemove(admission.ChallengeId, out _);
            if (_activeObservationAdmissions.TryGetValue(admission.GrantId, out var current) &&
                ReferenceEquals(current, admission))
            {
                _activeObservationAdmissions.TryRemove(admission.GrantId, out _);
            }
        }
    }

    /// <summary>
    /// Authenticate the endpoint and process its bounded active job list.
    /// Network failures leave a job in progress so a later poll can resume it.
    /// </summary>
    public async Task<IReadOnlyList<ReceivedEndpointFile>> PollAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!await _pollGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            return Array.Empty<ReceivedEndpointFile>();
        }

        try
        {
            var healthBytes = await _transport.SendAsync(
                HttpMethod.Get, "/health", null, cancellationToken, expectedStatusCode: 200)
                .ConfigureAwait(false);
            try
            {
                using var healthDocument = JsonDocument.Parse(healthBytes);
                var root = healthDocument.RootElement;
                if (root.ValueKind != JsonValueKind.Object ||
                    !root.TryGetProperty("schema_version", out var schemaVersion) ||
                    schemaVersion.ValueKind != JsonValueKind.Number || !schemaVersion.TryGetInt32(out var schema) || schema != 1 ||
                    !root.TryGetProperty("status", out var status) || status.ValueKind != JsonValueKind.String || status.GetString() != "ok" ||
                    !root.TryGetProperty("features", out var features) || features.ValueKind != JsonValueKind.Object ||
                    !features.TryGetProperty("file_jobs", out var fileJobs) || fileJobs.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    throw InvalidResponse("The deployment health response did not include valid file-delivery availability.");
                }
                if (!fileJobs.GetBoolean())
                {
                    throw new ServerClientException(
                        ServerClientFailure.NotAvailableInThisBuild,
                        "File delivery is not enabled by this deployment.");
                }
            }
            catch (JsonException exception)
            {
                throw InvalidResponse("The deployment health response was invalid.", exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(healthBytes);
            }

            using var keyStorage = new DeviceKeyStorage(_storageDirectory);
            var keyResult = keyStorage.Open(out var seed, out var storedPublicKey);
            try
            {
                if (keyResult != DeviceKeyStorageResult.Success || seed.Length != Ed25519DeviceKey.SeedLength ||
                    storedPublicKey.Length != Ed25519DeviceKey.PublicKeyLength)
                {
                    throw StorageFailure("The protected endpoint identity could not be opened.");
                }

                using var signingKey = Ed25519DeviceKey.ImportSeed(seed);
                var publicBytesValid = Ed25519DeviceKey.TryParsePublicKey(signingKey.PublicKeyHex, out var derivedPublicKey);
                try
                {
                    if (!publicBytesValid || derivedPublicKey.Length != storedPublicKey.Length ||
                        !CryptographicOperations.FixedTimeEquals(derivedPublicKey, storedPublicKey))
                    {
                        throw StorageFailure("The protected endpoint identity is inconsistent.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(derivedPublicKey);
                }

                var configuration = EndpointEnrollmentClient.ReadSavedConfiguration();
                if (configuration is null ||
                    !string.Equals(configuration.Trust.DeploymentId, _trust.DeploymentId, StringComparison.Ordinal) ||
                    !string.Equals(configuration.Trust.Origin.AbsoluteUri, _trust.Origin.AbsoluteUri, StringComparison.Ordinal) ||
                    !string.Equals(configuration.Trust.CaFingerprintSha256Hex, _trust.CaFingerprintSha256Hex, StringComparison.Ordinal))
                {
                    throw StorageFailure("Saved endpoint deployment trust is unavailable.");
                }

                var enrollment = configuration.Enrollment;
                var localUserId = GetCurrentEligibleLocalUserId();
                var localUserDisplayName = localUserId is null ? null : Environment.UserName;
                var session = await CurrentEndpointSessionAsync(
                    enrollment,
                    localUserId,
                    localUserDisplayName,
                    signingKey,
                    cancellationToken)
                    .ConfigureAwait(false);
                if (localUserId is null)
                {
                    throw new EndpointFileDeliveryWaitingForUserException(
                        "Waiting for an eligible signed-in console user.");
                }
                try
                {
                    RequireSameLocalUser(localUserId);
                }
                catch (EndpointFileDeliveryPausedException)
                {
                    var currentUserIsEligible = await RefreshSessionForCurrentConsoleAsync(enrollment, signingKey, cancellationToken)
                        .ConfigureAwait(false);
                    throw new EndpointFileDeliveryWaitingForUserException(currentUserIsEligible
                        ? "File delivery paused after a console-user change. It will check again shortly."
                        : "Waiting for an eligible signed-in console user.");
                }
                var jobs = await ReadJobsAsync(session.Token, cancellationToken).ConfigureAwait(false);
                if (jobs.Count > MaxJobs)
                {
                    throw InvalidResponse("The endpoint job list exceeded its size limit.");
                }
                try
                {
                    RequireSameLocalUser(localUserId);
                }
                catch (EndpointFileDeliveryPausedException)
                {
                    var currentUserIsEligible = await RefreshSessionForCurrentConsoleAsync(enrollment, signingKey, cancellationToken)
                        .ConfigureAwait(false);
                    throw new EndpointFileDeliveryWaitingForUserException(currentUserIsEligible
                        ? "File delivery paused after a console-user change. It will check again shortly."
                        : "Waiting for an eligible signed-in console user.");
                }

                var received = new List<ReceivedEndpointFile>();
                foreach (var job in jobs)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (job is null)
                    {
                        throw InvalidResponse("The endpoint job list contained an empty entry.");
                    }
                    try
                    {
                        var file = await ReceiveJobAsync(job, localUserId, session.Token, cancellationToken).ConfigureAwait(false);
                        received.Add(file);
                    }
                    catch (EndpointFileDeliveryPausedException)
                    {
                        // Replace the old session with an unbound session when the console
                        // user is no longer verifiable, then let the bound recipient resume.
                        var currentUserIsEligible = await RefreshSessionForCurrentConsoleAsync(enrollment, signingKey, cancellationToken)
                            .ConfigureAwait(false);
                        throw new EndpointFileDeliveryWaitingForUserException(currentUserIsEligible
                            ? "File delivery paused after a console-user change. It will check again shortly."
                            : "Waiting for an eligible signed-in console user.");
                    }
                    catch (EndpointFileDeliveryFailureException failure)
                    {
                        await ReportFailureAsync(job.Id, failure.Message, session.Token, cancellationToken)
                            .ConfigureAwait(false);
                    }
                }

                return received;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                CryptographicOperations.ZeroMemory(storedPublicKey);
            }
        }
        finally
        {
            _pollGate.Release();
        }
    }

    /// <summary>Lists only open file requests assigned to this computer.</summary>
    public async Task<IReadOnlyList<EndpointFileRequest>> ListAvailableFileRequestsAsync(
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _requestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var context = await CreateFileRequestSessionAsync(cancellationToken).ConfigureAwait(false);
            return await ReadAvailableFileRequestsAsync(context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _requestGate.Release();
        }
    }

    /// <summary>
    /// Lists prior submissions for this computer, request, and signed local
    /// Windows user. The server applies the same owner binding to every row.
    /// </summary>
    public async Task<IReadOnlyList<EndpointFileRequestSubmission>> ListMyFileRequestSubmissionsAsync(
        string requestId,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!IsCanonicalUuid(requestId))
        {
            throw InvalidResponse("The selected file request identity is invalid.");
        }

        await _requestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var context = await CreateFileRequestSessionAsync(cancellationToken).ConfigureAwait(false);
            return await ReadMyFileRequestSubmissionsAsync(context, requestId, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _requestGate.Release();
        }
    }

    /// <summary>
    /// Uploads user-selected files to an open request. Identical in-progress
    /// manifests resume by retrying their idempotent chunks. Replacing a
    /// received submission requires its exact ID and explicit confirmation.
    /// </summary>
    public async Task<EndpointFileRequestSubmission> SubmitFilesToRequestAsync(
        string requestId,
        long requestRevision,
        IReadOnlyList<string> filePaths,
        string? replaceSubmissionId,
        bool confirmReplacement,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!IsCanonicalUuid(requestId) || requestRevision <= 0 ||
            filePaths is null || filePaths.Count is < 1 or > 50)
        {
            throw InvalidResponse("Choose a current file request and between 1 and 50 files.");
        }
        if (replaceSubmissionId is not null &&
            (!IsCanonicalUuid(replaceSubmissionId) || !confirmReplacement))
        {
            throw InvalidResponse("Replacing a submission requires its exact ID and explicit confirmation.");
        }
        if (replaceSubmissionId is null && confirmReplacement)
        {
            throw InvalidResponse("A replacement submission ID is required for explicit replacement.");
        }

        await _requestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var context = await CreateFileRequestSessionAsync(cancellationToken).ConfigureAwait(false);
            var requests = await ReadAvailableFileRequestsAsync(context, cancellationToken).ConfigureAwait(false);
            var request = requests.FirstOrDefault(value => value.Id == requestId);
            if (request is null || request.Revision != requestRevision)
            {
                throw InvalidResponse("This file request changed or closed. Refresh the request list before submitting.");
            }

            var sources = await PrepareUploadSourcesAsync(filePaths, request, cancellationToken).ConfigureAwait(false);
            try
            {
                var history = await ReadMyFileRequestSubmissionsAsync(context, requestId, cancellationToken)
                    .ConfigureAwait(false);
                if (replaceSubmissionId is not null &&
                    (!request.ReplacementAllowed ||
                     !history.Any(value => value.Id == replaceSubmissionId && value.State == "received")))
                {
                    throw InvalidResponse("The selected submission cannot be replaced by this request or signed-in user.");
                }

                var submission = replaceSubmissionId is null
                    ? history.FirstOrDefault(value =>
                        value.State == "uploading" &&
                        value.RequestRevision == requestRevision &&
                        MatchesManifest(value.Files, sources))
                    : null;
                if (submission is null)
                {
                    RequireSameLocalUser(context.LocalUserId);
                    var manifest = sources.Select(source => new FileRequestSubmissionFileManifest(
                        source.FileName,
                        source.FileSizeBytes,
                        source.Sha256)).ToList();
                    var created = await PostJsonAsync<EndpointFileRequestSubmissionDto>(
                        $"/v2/endpoints/file-requests/{requestId}/submissions",
                        new CreateFileRequestSubmissionRequest(
                            requestRevision,
                            manifest,
                            replaceSubmissionId,
                            confirmReplacement),
                        expectedStatus: 201,
                        context.Session.Token,
                        cancellationToken).ConfigureAwait(false);
                    submission = ValidateSubmission(created, context, requestId);
                }

                if (submission.State != "uploading" ||
                    submission.RequestRevision != requestRevision ||
                    submission.RequestId != requestId)
                {
                    throw InvalidResponse("The server returned a submission that does not match the selected request.");
                }

                if (submission.Files.Count != sources.Count)
                {
                    throw InvalidResponse("The server submission manifest does not match the selected files.");
                }
                var filesByName = new Dictionary<string, EndpointFileRequestSubmissionFile>(StringComparer.Ordinal);
                foreach (var file in submission.Files)
                {
                    if (!filesByName.TryAdd(file.FileName, file))
                    {
                        throw InvalidResponse("The server returned duplicate file names in the submission.");
                    }
                }
                foreach (var source in sources)
                {
                    if (!filesByName.TryGetValue(source.FileName, out var file) ||
                        !IsCanonicalUuid(file.Id) ||
                        !string.Equals(file.Sha256, source.Sha256, StringComparison.Ordinal) ||
                        file.FileSizeBytes != source.FileSizeBytes)
                    {
                        throw InvalidResponse("The server submission manifest does not match the selected files.");
                    }
                    source.FileId = file.Id;
                }

                foreach (var source in sources)
                {
                    await UploadSourceAsync(source, request, submission, context, cancellationToken)
                        .ConfigureAwait(false);
                }

                RequireSameLocalUser(context.LocalUserId);
                RequireSessionCurrent(context.Session);
                var completed = await PostJsonAsync<EndpointFileRequestSubmissionDto>(
                    $"/v2/endpoints/file-requests/{requestId}/submissions/{submission.Id}/complete",
                    new CompleteFileRequestSubmissionRequest(requestRevision, submission.Id),
                    expectedStatus: 200,
                    context.Session.Token,
                    cancellationToken).ConfigureAwait(false);
                var result = ValidateSubmission(completed, context, requestId);
                if (result.Id != submission.Id || result.State != "received" ||
                    result.Files.Any(file => file.State != "received"))
                {
                    throw InvalidResponse("The server did not verify every submitted file.");
                }
                RequireSameLocalUser(context.LocalUserId);
                return result;
            }
            finally
            {
                foreach (var source in sources)
                {
                    source.Dispose();
                }
            }
        }
        finally
        {
            _requestGate.Release();
        }
    }

    private async Task<FileRequestSessionContext> CreateFileRequestSessionAsync(
        CancellationToken cancellationToken)
    {
        await EnsureFileRequestsEnabledAsync(cancellationToken).ConfigureAwait(false);
        var configuration = EndpointEnrollmentClient.ReadSavedConfiguration();
        if (configuration is null ||
            !string.Equals(configuration.Trust.DeploymentId, _trust.DeploymentId, StringComparison.Ordinal) ||
            !string.Equals(configuration.Trust.Origin.AbsoluteUri, _trust.Origin.AbsoluteUri, StringComparison.Ordinal) ||
            !string.Equals(configuration.Trust.CaFingerprintSha256Hex, _trust.CaFingerprintSha256Hex, StringComparison.Ordinal))
        {
            throw StorageFailure("Saved endpoint deployment trust is unavailable.");
        }

        var enrollment = configuration.Enrollment;
        var localUserId = GetCurrentEligibleLocalUserId();
        if (localUserId is null)
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "File requests are available only to a signed-in user at the physical console.");
        }
        var displayName = Environment.UserName;
        if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 128 ||
            displayName.Any(char.IsControl))
        {
            throw new EndpointFileDeliveryWaitingForUserException(
                "Windows could not verify the current console user's account label.");
        }

        using var keyStorage = new DeviceKeyStorage(_storageDirectory);
        var keyResult = keyStorage.Open(out var seed, out var storedPublicKey);
        try
        {
            if (keyResult != DeviceKeyStorageResult.Success ||
                seed.Length != Ed25519DeviceKey.SeedLength ||
                storedPublicKey.Length != Ed25519DeviceKey.PublicKeyLength)
            {
                throw StorageFailure("The protected endpoint identity could not be opened.");
            }

            using var signingKey = Ed25519DeviceKey.ImportSeed(seed);
            var publicBytesValid = Ed25519DeviceKey.TryParsePublicKey(signingKey.PublicKeyHex, out var derivedPublicKey);
            try
            {
                if (!publicBytesValid || derivedPublicKey.Length != storedPublicKey.Length ||
                    !CryptographicOperations.FixedTimeEquals(derivedPublicKey, storedPublicKey))
                {
                    throw StorageFailure("The protected endpoint identity is inconsistent.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedPublicKey);
            }

            var session = await CurrentEndpointSessionAsync(
                enrollment,
                localUserId,
                displayName,
                signingKey,
                cancellationToken).ConfigureAwait(false);
            try
            {
                RequireSameLocalUser(localUserId);
            }
            catch (EndpointFileDeliveryPausedException)
            {
                await RefreshSessionForCurrentConsoleAsync(enrollment, signingKey, cancellationToken)
                    .ConfigureAwait(false);
                throw new EndpointFileDeliveryWaitingForUserException(
                    "File request activity paused after the physical-console user changed.");
            }

            return new FileRequestSessionContext(
                enrollment.ComputerId,
                localUserId,
                displayName,
                session);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(storedPublicKey);
        }
    }

    private async Task EnsureFileRequestsEnabledAsync(CancellationToken cancellationToken)
    {
        var healthBytes = await _transport.SendAsync(
            HttpMethod.Get,
            "/health",
            content: null,
            cancellationToken,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            using var healthDocument = JsonDocument.Parse(healthBytes);
            var root = healthDocument.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schema_version", out var schemaVersion) ||
                schemaVersion.ValueKind != JsonValueKind.Number ||
                !schemaVersion.TryGetInt32(out var schema) || schema != 1 ||
                !root.TryGetProperty("status", out var status) ||
                status.ValueKind != JsonValueKind.String || status.GetString() != "ok" ||
                !root.TryGetProperty("features", out var features) ||
                features.ValueKind != JsonValueKind.Object)
            {
                throw InvalidResponse("The deployment health response did not include valid file-request availability.");
            }
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The deployment health response was invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(healthBytes);
        }
    }

    private async Task EnsureObservationEnabledAsync(CancellationToken cancellationToken)
    {
        var healthBytes = await _transport.SendAsync(
            HttpMethod.Get,
            "/health",
            content: null,
            cancellationToken,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(healthBytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("features", out var features) ||
                features.ValueKind != JsonValueKind.Object)
            {
                throw InvalidResponse(
                    "The deployment health response did not include valid screen-observation availability.");
            }
            if (!features.TryGetProperty("screen_observation", out var screenObservation))
            {
                throw new ServerClientException(
                    ServerClientFailure.NotAvailableInThisBuild,
                    "Screen observation is not available from this deployment.");
            }
            if (screenObservation.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                throw InvalidResponse(
                    "The deployment health response did not include valid screen-observation availability.");
            }
            if (!screenObservation.GetBoolean())
            {
                throw new ServerClientException(
                    ServerClientFailure.NotAvailableInThisBuild,
                    "Screen observation is not enabled by this deployment.");
            }
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The deployment health response was invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(healthBytes);
        }
    }

    private async Task<IReadOnlyList<EndpointFileRequest>> ReadAvailableFileRequestsAsync(
        FileRequestSessionContext context,
        CancellationToken cancellationToken)
    {
        RequireSameLocalUser(context.LocalUserId);
        RequireSessionCurrent(context.Session);
        var bytes = await _transport.SendAsync(
            HttpMethod.Get,
            "/v2/endpoints/file-requests",
            content: null,
            cancellationToken,
            context.Session.Token,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            var response = JsonSerializer.Deserialize<EndpointFileRequestListResponse>(bytes, JsonOptions)
                ?? throw InvalidResponse("The endpoint file-request response was empty.");
            if (response.Requests is null || response.Requests.Count > MaxRequests ||
                response.MaxPageSize is < 1 or > MaxRequests ||
                response.Requests.Count > response.MaxPageSize)
            {
                throw InvalidResponse("The endpoint file-request response exceeded its size limit.");
            }

            var seenIds = new HashSet<string>(StringComparer.Ordinal);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var requests = new List<EndpointFileRequest>(response.Requests.Count);
            foreach (var request in response.Requests)
            {
                if (request is null || !IsCanonicalUuid(request.Id) || !seenIds.Add(request.Id) ||
                    request.Revision <= 0 || string.IsNullOrWhiteSpace(request.Title) ||
                    request.Title.Length > 120 || request.Title.Any(char.IsControl) ||
                    request.Instructions is null || request.Instructions.Length > 2000 ||
                    request.Instructions.Any(character =>
                        char.IsControl(character) && character is not '\n' and not '\r' and not '\t') ||
                    request.AllowedExtensions is null ||
                    !AreValidRequestExtensions(request.AllowedExtensions) ||
                    request.MaxFileCount is < 1 or > 50 ||
                    request.MaxTotalSizeBytes is < 1 or > MaxFileBytes ||
                    request.ClosesAtUnix <= now ||
                    request.ClosesAtUnix > now + 30L * 24 * 60 * 60)
                {
                    throw InvalidResponse("The server returned invalid file-request metadata.");
                }
                requests.Add(new EndpointFileRequest(
                    request.Id,
                    request.Revision,
                    request.Title,
                    request.Instructions,
                    request.AllowedExtensions,
                    request.MaxFileCount,
                    request.MaxTotalSizeBytes,
                    request.ClosesAtUnix,
                    request.ReplacementAllowed));
            }
            RequireSameLocalUser(context.LocalUserId);
            return requests;
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The endpoint file-request response was invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<IReadOnlyList<EndpointFileRequestSubmission>> ReadMyFileRequestSubmissionsAsync(
        FileRequestSessionContext context,
        string requestId,
        CancellationToken cancellationToken)
    {
        RequireSameLocalUser(context.LocalUserId);
        RequireSessionCurrent(context.Session);
        var bytes = await _transport.SendAsync(
            HttpMethod.Get,
            $"/v2/endpoints/file-requests/{requestId}/submissions",
            content: null,
            cancellationToken,
            context.Session.Token,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            var response = JsonSerializer.Deserialize<List<EndpointFileRequestSubmissionDto>>(bytes, JsonOptions)
                ?? throw InvalidResponse("The endpoint submission response was empty.");
            if (response.Count > MaxRequests)
            {
                throw InvalidResponse("The endpoint submission response exceeded its size limit.");
            }
            var seenIds = new HashSet<string>(StringComparer.Ordinal);
            var submissions = response.Select(record =>
            {
                if (record is null || !IsCanonicalUuid(record.Id) || !seenIds.Add(record.Id))
                {
                    throw InvalidResponse("The server returned an invalid submission identity.");
                }
                return ValidateSubmission(record, context, requestId);
            }).ToList();
            RequireSameLocalUser(context.LocalUserId);
            return submissions;
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The endpoint submission response was invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static EndpointFileRequestSubmission ValidateSubmission(
        EndpointFileRequestSubmissionDto record,
        FileRequestSessionContext context,
        string requestId)
    {
        if (!IsCanonicalUuid(record.Id) || !IsCanonicalUuid(record.RequestId) ||
            !IsCanonicalUuid(record.ComputerId) ||
            !IsCanonicalUuid(requestId) ||
            record.RequestId != requestId || record.ComputerId != context.ComputerId ||
            record.RequestRevision <= 0 ||
            !string.Equals(record.LocalUserDisplayName, context.LocalUserDisplayName, StringComparison.Ordinal) ||
            record.CreatedAtUnix <= 0 ||
            record.CreatedAtUnix > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300 ||
            record.State is not ("uploading" or "received" or "failed" or "expired" or "superseded") ||
            record.Files is null || record.Files.Count is < 1 or > 50 ||
            (record.ReplacesSubmissionId is not null && !IsCanonicalUuid(record.ReplacesSubmissionId)))
        {
            throw InvalidResponse("The server returned a submission outside this endpoint user's scope.");
        }

        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenFileIds = new HashSet<string>(StringComparer.Ordinal);
        var files = new List<EndpointFileRequestSubmissionFile>(record.Files.Count);
        ulong totalSize = 0;
        foreach (var file in record.Files)
        {
            if (file is null || !IsCanonicalUuid(file.Id) || !seenFileIds.Add(file.Id) ||
                !IsSafeFileName(file.FileName) ||
                !seenNames.Add(file.FileName) || file.FileSizeBytes > MaxFileBytes ||
                file.FileSizeBytes > MaxFileBytes - totalSize ||
                !IsLowerSha256(file.Sha256) || file.ChunkSizeBytes != ChunkSize ||
                file.ChunkCount != (file.FileSizeBytes == 0
                    ? 0
                    : (file.FileSizeBytes + ChunkSize - 1) / ChunkSize) ||
                file.State is not ("uploading" or "received" or "failed" or "deleted"))
            {
                throw InvalidResponse("The server returned invalid submission-file metadata.");
            }
            totalSize += file.FileSizeBytes;
            files.Add(new EndpointFileRequestSubmissionFile(
                file.Id,
                file.FileName,
                file.FileSizeBytes,
                file.Sha256,
                file.State));
        }
        return new EndpointFileRequestSubmission(
            record.Id,
            record.RequestId,
            record.RequestRevision,
            record.ComputerId,
            record.LocalUserDisplayName,
            record.State,
            record.CreatedAtUnix,
            files);
    }

    private async Task<List<PreparedUploadSource>> PrepareUploadSourcesAsync(
        IReadOnlyList<string> paths,
        EndpointFileRequest request,
        CancellationToken cancellationToken)
    {
        if (paths.Count > request.MaxFileCount)
        {
            throw new ArgumentException("The request allows fewer files than you selected.");
        }
        var sources = new List<PreparedUploadSource>(paths.Count);
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ulong totalSize = 0;
        try
        {
            foreach (var path in paths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(path))
                {
                    throw new ArgumentException("A selected file path is empty.");
                }
                var fullPath = Path.GetFullPath(path);
                var fileName = Path.GetFileName(fullPath);
                if (!IsSafeFileName(fileName) || !seenNames.Add(fileName))
                {
                    throw new ArgumentException("Selected file names must be safe and unique without case sensitivity.");
                }
                if (!IsExtensionAllowed(fileName, request.AllowedExtensions))
                {
                    throw new ArgumentException($"The file {fileName} does not match this request's allowed types.");
                }

                var handle = FileSecurityNative.CreateFileW(
                    fullPath,
                    FileSecurityNative.GenericRead,
                    FileSecurityNative.FileShareRead,
                    IntPtr.Zero,
                    FileSecurityNative.OpenExisting,
                    FileSecurityNative.FileFlagOpenReparsePoint,
                    IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    handle.Dispose();
                    throw new IOException("A selected file could not be opened safely.");
                }
                FileStream stream;
                try
                {
                    if (!Kernel32Native.GetFileInformationByHandle(handle.DangerousGetHandle(), out var info) ||
                        (info.dwFileAttributes & (FileSecurityNative.FileAttributeReparsePoint | 0x10)) != 0)
                    {
                        throw new IOException("A selected file is not a regular local file.");
                    }
                    stream = new FileStream(handle, FileAccess.Read, ChunkSize, isAsync: false);
                }
                catch
                {
                    handle.Dispose();
                    throw;
                }

                var retainStream = false;
                try
                {
                    var fileSize = checked((ulong)stream.Length);
                    if (fileSize > MaxFileBytes || fileSize > request.MaxTotalSizeBytes - totalSize)
                    {
                        throw new ArgumentException("The selected files exceed this request's size limit.");
                    }
                    totalSize += fileSize;
                    var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
                    var digest = Convert.ToHexString(hash).ToLowerInvariant();
                    CryptographicOperations.ZeroMemory(hash);
                    stream.Position = 0;
                    sources.Add(new PreparedUploadSource(
                        stream,
                        fileName,
                        fileSize,
                        digest));
                    retainStream = true;
                }
                finally
                {
                    if (!retainStream)
                    {
                        stream.Dispose();
                    }
                }
            }
            return sources;
        }
        catch
        {
            foreach (var source in sources)
            {
                source.Dispose();
            }
            throw;
        }
    }

    private async Task UploadSourceAsync(
        PreparedUploadSource source,
        EndpointFileRequest request,
        EndpointFileRequestSubmission submission,
        FileRequestSessionContext context,
        CancellationToken cancellationToken)
    {
        var fileId = source.FileId;
        if (fileId is null)
        {
            throw InvalidResponse("The server did not assign an identifier to a submitted file.");
        }
        source.Stream.Position = 0;
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        ulong uploadedBytes = 0;
        var chunkCount = source.FileSizeBytes == 0
            ? 0
            : (source.FileSizeBytes + ChunkSize - 1) / ChunkSize;
        for (uint index = 0; index < chunkCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireSameLocalUser(context.LocalUserId);
            RequireSessionCurrent(context.Session);
            var offset = (ulong)index * ChunkSize;
            var length = (int)Math.Min((ulong)ChunkSize, source.FileSizeBytes - offset);
            var chunk = new byte[length];
            try
            {
                await ReadExactlyAsync(source.Stream, chunk, cancellationToken).ConfigureAwait(false);
                hasher.AppendData(chunk);
                uploadedBytes += (ulong)chunk.Length;

                using var content = new ByteArrayContent(chunk);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                var receiptBytes = await _transport.SendAsync(
                    HttpMethod.Put,
                    $"/v2/endpoints/file-requests/{request.Id}/submissions/{submission.Id}/files/{fileId}/chunks/{index}",
                    content,
                    cancellationToken,
                    context.Session.Token,
                    expectedStatusCode: 200).ConfigureAwait(false);
                try
                {
                    var receipt = JsonSerializer.Deserialize<EndpointFileRequestChunkReceipt>(receiptBytes, JsonOptions)
                        ?? throw InvalidResponse("The server returned an empty chunk receipt.");
                    var chunkHash = Convert.ToHexString(SHA256.HashData(chunk)).ToLowerInvariant();
                    if (receipt.SubmissionId != submission.Id || receipt.FileId != fileId ||
                        receipt.ChunkIndex != index || receipt.Sha256 != chunkHash)
                    {
                        throw InvalidResponse("The server returned a chunk receipt for different file data.");
                    }
                }
                catch (JsonException exception)
                {
                    throw InvalidResponse("The server returned an invalid chunk receipt.", exception);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(receiptBytes);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(chunk);
            }
        }

        var uploadedDigest = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        if (uploadedBytes != source.FileSizeBytes || source.Stream.ReadByte() != -1 ||
            !string.Equals(uploadedDigest, source.Sha256, StringComparison.Ordinal))
        {
            throw new IOException("A selected file changed while it was being uploaded. The partial submission can be resumed.");
        }
        RequireSameLocalUser(context.LocalUserId);
        RequireSessionCurrent(context.Session);
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new IOException("A selected file changed while it was being uploaded.");
            }
            offset += count;
        }
    }

    private static bool MatchesManifest(
        IReadOnlyList<EndpointFileRequestSubmissionFile> files,
        IReadOnlyList<PreparedUploadSource> sources)
    {
        if (files.Count != sources.Count)
        {
            return false;
        }
        return sources.All(source => files.Any(file =>
            string.Equals(file.FileName, source.FileName, StringComparison.Ordinal) &&
            file.FileSizeBytes == source.FileSizeBytes &&
            string.Equals(file.Sha256, source.Sha256, StringComparison.Ordinal)));
    }

    private static bool AreValidRequestExtensions(IReadOnlyList<string> values)
    {
        if (values.Count is < 1 or > 64)
        {
            return false;
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 32 ||
                value != value.ToLowerInvariant() ||
                (value != "*" && value.Any(character =>
                    !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '+' or '_' or '-'))) ||
                (value != "*" && (value.StartsWith('.') || value.EndsWith('.') || value.Contains(".."))) ||
                !seen.Add(value))
            {
                return false;
            }
        }
        return !seen.Contains("*") || values.Count == 1;
    }

    private static bool IsExtensionAllowed(string fileName, IReadOnlyList<string> allowedExtensions)
    {
        if (allowedExtensions.Contains("*", StringComparer.Ordinal))
        {
            return true;
        }
        return allowedExtensions.Any(extension =>
            fileName.EndsWith($".{extension}", StringComparison.OrdinalIgnoreCase) &&
            fileName.Length > extension.Length + 1);
    }

    private static void RequireSessionCurrent(EndpointSession session)
    {
        if (session.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The endpoint file-request session expired. Refresh the request and resume the upload.");
        }
    }

    private async Task<EndpointSession> AuthenticateAsync(
        string computerId,
        string? localUserId,
        string? localUserDisplayName,
        Ed25519DeviceKey signingKey,
        CancellationToken cancellationToken)
    {
        var nonceBytes = RandomNumberGenerator.GetBytes(32);
        try
        {
            var nonce = Ed25519DeviceKey.ToLowerHex(nonceBytes);
            var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var displayNameHex = localUserDisplayName is null
                ? null
                : Convert.ToHexString(Encoding.UTF8.GetBytes(localUserDisplayName)).ToLowerInvariant();
            var beginMessage = localUserId is null
                ? $"hs-endpoint-session-begin-v1|deployment:{_trust.DeploymentId}|computer:{computerId}|issued_at:{issuedAt}|nonce:{nonce}"
                : localUserDisplayName is not null
                    ? $"hs-endpoint-session-begin-v3|deployment:{_trust.DeploymentId}|computer:{computerId}|local_user:{localUserId}|local_user_display_name:{displayNameHex}|issued_at:{issuedAt}|nonce:{nonce}"
                    : $"hs-endpoint-session-begin-v2|deployment:{_trust.DeploymentId}|computer:{computerId}|local_user:{localUserId}|issued_at:{issuedAt}|nonce:{nonce}";
            var begin = Encoding.UTF8.GetBytes(beginMessage);
            var signature = signingKey.Sign(begin);
            try
            {
                var challenge = await PostJsonAsync<EndpointSessionChallenge>(
                    "/v2/endpoints/session/challenge",
                    new EndpointSessionChallengeRequest(
                        computerId,
                        localUserId,
                        localUserDisplayName,
                        nonce,
                        issuedAt,
                        Ed25519DeviceKey.ToLowerHex(signature)),
                    expectedStatus: 201,
                    bearerToken: null,
                    cancellationToken).ConfigureAwait(false);
                if (challenge.ChallengeId is null || challenge.ChallengeToken is null ||
                    challenge.DeploymentId is null || challenge.ComputerId is null ||
                    !IsCanonicalUuid(challenge.ChallengeId) ||
                    challenge.DeploymentId != _trust.DeploymentId ||
                    challenge.ComputerId != computerId || challenge.EnrollmentEpoch <= 0 ||
                    challenge.ExpiresAtUnix <= issuedAt || challenge.ExpiresAtUnix > issuedAt + 120 ||
                    !IsToken(challenge.ChallengeToken, 43, 43))
                {
                    throw InvalidResponse("The endpoint challenge did not match the saved deployment identity.");
                }

                var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(challenge.ChallengeToken)))
                    .ToLowerInvariant();
                var completionMessage = localUserId is null
                    ? $"hs-endpoint-session-v1|deployment:{_trust.DeploymentId}|challenge:{challenge.ChallengeId}|token_hash:{tokenHash}|computer:{computerId}|epoch:{challenge.EnrollmentEpoch}|endpoint:{signingKey.PublicKeyHex}"
                    : localUserDisplayName is not null
                        ? $"hs-endpoint-session-v3|deployment:{_trust.DeploymentId}|challenge:{challenge.ChallengeId}|token_hash:{tokenHash}|computer:{computerId}|epoch:{challenge.EnrollmentEpoch}|endpoint:{signingKey.PublicKeyHex}|local_user:{localUserId}|local_user_display_name:{displayNameHex}"
                        : $"hs-endpoint-session-v2|deployment:{_trust.DeploymentId}|challenge:{challenge.ChallengeId}|token_hash:{tokenHash}|computer:{computerId}|epoch:{challenge.EnrollmentEpoch}|endpoint:{signingKey.PublicKeyHex}|local_user:{localUserId}";
                var completion = Encoding.UTF8.GetBytes(completionMessage);
                var completionSignature = signingKey.Sign(completion);
                try
                {
                    var session = await PostJsonAsync<EndpointSession>(
                        "/v2/endpoints/session/complete",
                        new EndpointSessionCompleteRequest(
                            challenge.ChallengeId,
                            challenge.ChallengeToken,
                            Ed25519DeviceKey.ToLowerHex(completionSignature)),
                        expectedStatus: 200,
                        bearerToken: null,
                        cancellationToken).ConfigureAwait(false);
                    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    if (session.Token is null || session.SessionId is null || session.DeploymentId is null || session.ComputerId is null ||
                        !IsCanonicalUuid(session.SessionId) ||
                        session.DeploymentId != _trust.DeploymentId || session.ComputerId != computerId ||
                        session.EnrollmentEpoch != challenge.EnrollmentEpoch ||
                        !IsToken(session.Token, 32, 128) || session.ExpiresAtUnix <= now ||
                        session.ExpiresAtUnix > now + 15 * 60)
                    {
                        throw InvalidResponse("The endpoint session did not match the approved endpoint identity.");
                    }

                    return session;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(completion);
                    CryptographicOperations.ZeroMemory(completionSignature);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(begin);
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonceBytes);
        }
    }

    private async Task<EndpointSession> CurrentEndpointSessionAsync(
        EndpointEnrollmentResult enrollment,
        string? localUserId,
        string? localUserDisplayName,
        Ed25519DeviceKey signingKey,
        CancellationToken cancellationToken)
    {
        await VerifyAuthorityCheckpointAsync(cancellationToken).ConfigureAwait(false);
        await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_currentSession is { } cached &&
                string.Equals(_currentSessionLocalUserId, localUserId, StringComparison.Ordinal) &&
                cached.ExpiresAtUnix > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30)
            {
                try
                {
                    await VerifySelfAsync(cached, enrollment, cancellationToken).ConfigureAwait(false);
                    return cached;
                }
                catch (ServerClientException exception) when (exception.Failure == ServerClientFailure.Unauthorized)
                {
                    _currentSession = null;
                    _currentSessionLocalUserId = null;
                }
            }

            var session = await AuthenticateAsync(
                enrollment.ComputerId,
                localUserId,
                localUserDisplayName,
                signingKey,
                cancellationToken).ConfigureAwait(false);
            await VerifySelfAsync(session, enrollment, cancellationToken).ConfigureAwait(false);
            _currentSession = session;
            _currentSessionLocalUserId = localUserId;
            return session;
        }
        finally
        {
            _sessionGate.Release();
        }
    }

    private async Task<bool> RefreshSessionForCurrentConsoleAsync(
        EndpointEnrollmentResult enrollment,
        Ed25519DeviceKey signingKey,
        CancellationToken cancellationToken)
    {
        var currentLocalUserId = GetCurrentEligibleLocalUserId();
        var currentLocalUserDisplayName = currentLocalUserId is null ? null : Environment.UserName;
        await CurrentEndpointSessionAsync(
            enrollment,
            currentLocalUserId,
            currentLocalUserDisplayName,
            signingKey,
            cancellationToken).ConfigureAwait(false);
        return currentLocalUserId is not null;
    }

    private async Task VerifySelfAsync(
        EndpointSession session,
        EndpointEnrollmentResult enrollment,
        CancellationToken cancellationToken)
    {
        var bytes = await _transport.SendAsync(
            HttpMethod.Get,
            "/v2/endpoints/self",
            content: null,
            cancellationToken,
            session.Token,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var root = document.RootElement;
            if (GetString(root, "computer_id") != enrollment.ComputerId ||
                GetString(root, "platform") != "windows" ||
                root.GetProperty("enrollment_epoch").GetInt64() != session.EnrollmentEpoch)
            {
                throw InvalidResponse("The server returned a different endpoint identity.");
            }
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The endpoint identity response was invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<List<EndpointFileJob>> ReadJobsAsync(string bearerToken, CancellationToken cancellationToken)
    {
        var bytes = await _transport.SendAsync(
            HttpMethod.Get,
            JobsPath,
            content: null,
            cancellationToken,
            bearerToken,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            var response = JsonSerializer.Deserialize<EndpointFileJobList>(bytes, JsonOptions)
                ?? throw InvalidResponse("The endpoint job response was empty.");
            return response.Jobs ?? throw InvalidResponse("The endpoint job response did not include a job list.");
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The endpoint job response was invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<ReceivedEndpointFile> ReceiveJobAsync(
        EndpointFileJob job,
        string localUserId,
        string bearerToken,
        CancellationToken cancellationToken)
    {
        RequireSameLocalUser(localUserId);
        if (!IsCanonicalUuid(job.Id))
        {
            throw InvalidResponse("The server returned a file job with an invalid identifier.");
        }
        if (job.FileName is null || job.Sha256 is null || job.State is null ||
            !IsSafeFileName(job.FileName) ||
            job.FileSizeBytes > MaxFileBytes || job.ChunkSizeBytes != ChunkSize ||
            job.ChunkCount != (job.FileSizeBytes == 0 ? 0 : (job.FileSizeBytes + ChunkSize - 1) / ChunkSize) ||
            !string.Equals(job.State, "in_progress", StringComparison.Ordinal) || !IsLowerSha256(job.Sha256))
        {
            throw new EndpointFileDeliveryFailureException("The server returned invalid file-job metadata.");
        }

        var directory = GetReceivedFilesDirectory();
        using var receivedDirectoryPin = PinReceivedFilesDirectory(directory);
        var outputName = BuildOutputFileName(job.Id, job.FileName);
        var finalPath = Path.Combine(directory, outputName);
        if (TryGetAttributes(finalPath, out var existingAttributes))
        {
            if (existingAttributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new EndpointFileDeliveryFailureException("The job destination is not a regular local file.");
            }
            if (existingAttributes.HasFlag(FileAttributes.Directory))
            {
                throw new EndpointFileDeliveryFailureException("A directory already occupies this job's destination.");
            }
            if (await MatchesFileAsync(finalPath, job.FileSizeBytes, job.Sha256, cancellationToken).ConfigureAwait(false))
            {
                RequireSameLocalUser(localUserId);
                using var existingDirectoryPin = PinReceivedFilesDirectory(directory);
                await ReportSuccessAsync(job, bearerToken, cancellationToken).ConfigureAwait(false);
                return new ReceivedEndpointFile(job.Id, job.FileName, finalPath);
            }
            throw new EndpointFileDeliveryFailureException("A different local file already occupies this job's destination.");
        }

        var temporaryPath = Path.Combine(directory, $".{job.Id}.{Guid.NewGuid():N}.part");
        try
        {
            await using (var output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                ChunkSize,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                ulong receivedSize = 0;
                for (uint index = 0; index < job.ChunkCount; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    RequireSameLocalUser(localUserId);
                    var chunk = await _transport.SendAsync(
                        HttpMethod.Get,
                        $"/v2/endpoints/jobs/{job.Id}/chunks/{index}",
                        content: null,
                        cancellationToken,
                        bearerToken,
                        expectedStatusCode: 200).ConfigureAwait(false);
                    try
                    {
                        var offset = (long)index * job.ChunkSizeBytes;
                        var expectedLength = (int)Math.Min(
                            (ulong)job.ChunkSizeBytes,
                            job.FileSizeBytes - (ulong)offset);
                        if (chunk.Length != expectedLength)
                        {
                            throw new EndpointFileDeliveryFailureException("A received file chunk had an unexpected size.");
                        }
                        await output.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);
                        hasher.AppendData(chunk);
                        receivedSize += (ulong)chunk.Length;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(chunk);
                    }
                }

                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
                var digest = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
                if (receivedSize != job.FileSizeBytes || !string.Equals(digest, job.Sha256, StringComparison.Ordinal))
                {
                    throw new EndpointFileDeliveryFailureException("The received file failed its full-file integrity check.");
                }
            }

            using var commitDirectoryPin = PinReceivedFilesDirectory(directory);
            RequireSameLocalUser(localUserId);
            try
            {
                File.Move(temporaryPath, finalPath, overwrite: false);
            }
            catch (IOException) when (TryGetAttributes(finalPath, out _))
            {
                if (!await MatchesFileAsync(finalPath, job.FileSizeBytes, job.Sha256, cancellationToken).ConfigureAwait(false))
                {
                    throw new EndpointFileDeliveryFailureException("The verified file could not be published without replacing another file.");
                }
            }

            RequireSameLocalUser(localUserId);
            await ReportSuccessAsync(job, bearerToken, cancellationToken).ConfigureAwait(false);
            return new ReceivedEndpointFile(job.Id, job.FileName, finalPath);
        }
        finally
        {
            TryDeleteOwnedTemporary(temporaryPath);
        }
    }

    private async Task ReportSuccessAsync(EndpointFileJob job, string bearerToken, CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new EndpointFileJobResult(
            true,
            null,
            job.FileSizeBytes,
            job.Sha256), JsonOptions);
        try
        {
            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            var response = await _transport.SendAsync(
                HttpMethod.Post,
                $"/v2/endpoints/jobs/{job.Id}/result",
                content,
                cancellationToken,
                bearerToken,
                expectedStatusCode: 200).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(response);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    private static void RequireSameLocalUser(string expectedLocalUserId)
    {
        if (!string.Equals(GetCurrentEligibleLocalUserId(), expectedLocalUserId, StringComparison.Ordinal))
        {
            throw new EndpointFileDeliveryPausedException(
                "The verified physical-console user changed before the file could be committed.");
        }
    }

    private static IDisposable PinReceivedFilesDirectory(string directory)
    {
        if (DeviceKeyStorage.TryPinDirectory(directory, out var pin) != DeviceKeyStorageResult.Success ||
            pin is null)
        {
            throw new EndpointFileDeliveryFailureException(
                "The private Received Files directory changed or is no longer owned by this user.");
        }
        return pin;
    }

    private static string? GetCurrentEligibleLocalUserId()
    {
        var consoleSession = Native.WtsNative.WTSGetActiveConsoleSessionId();
        if (consoleSession is 0 or uint.MaxValue ||
            !Native.WtsNative.ProcessIdToSessionId(Native.Kernel32Native.GetCurrentProcessId(), out var processSession) ||
            processSession != consoleSession)
        {
            return null;
        }

        var sid = WorkerSupervisor.GetCurrentProcessTokenSid();
        return string.IsNullOrWhiteSpace(sid) ? null : $"windows:sid:{sid}";
    }

    internal static bool IsObservationLeaseCurrent(string expectedLocalUserId)
    {
        return string.Equals(
                   GetCurrentEligibleLocalUserId(),
                   expectedLocalUserId,
                   StringComparison.Ordinal)
               && PhysicalConsoleObserver.Observe().IsEligible;
    }

    private async Task ReportFailureAsync(
        string jobId,
        string detail,
        string bearerToken,
        CancellationToken cancellationToken)
    {
        var safeDetail = new string(detail.Where(character => !char.IsControl(character)).Take(512).ToArray());
        var body = JsonSerializer.SerializeToUtf8Bytes(new EndpointFileJobResult(false, safeDetail, null, null), JsonOptions);
        try
        {
            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            var response = await _transport.SendAsync(
                HttpMethod.Post,
                $"/v2/endpoints/jobs/{jobId}/result",
                content,
                cancellationToken,
                bearerToken,
                expectedStatusCode: 200).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(response);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    private Task<T> PostJsonAsync<T>(
        string path,
        object value,
        int expectedStatus,
        string? bearerToken,
        CancellationToken cancellationToken)
    {
        return PostJsonCoreAsync<T>(path, value, expectedStatus, bearerToken, cancellationToken);
    }

    private async Task<T> PostJsonCoreAsync<T>(
        string path,
        object value,
        int expectedStatus,
        string? bearerToken,
        CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(value, value.GetType(), JsonOptions);
        try
        {
            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            var response = await _transport.SendAsync(
                HttpMethod.Post,
                path,
                content,
                cancellationToken,
                bearerToken,
                expectedStatus).ConfigureAwait(false);
            try
            {
                return JsonSerializer.Deserialize<T>(response, JsonOptions)
                    ?? throw InvalidResponse("The deployment returned an empty endpoint response.");
            }
            catch (JsonException exception)
            {
                throw InvalidResponse("The deployment returned an invalid endpoint response.", exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(response);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    private static bool IsCanonicalUuid(string value) =>
        Guid.TryParseExact(value, "D", out var parsed) &&
        string.Equals(parsed.ToString("D"), value, StringComparison.Ordinal);

    private static string ObservationSignalKindText(ObservationSignalKind kind) => kind switch
    {
        ObservationSignalKind.Challenge => "challenge",
        ObservationSignalKind.Offer => "offer",
        ObservationSignalKind.Answer => "answer",
        ObservationSignalKind.Ice => "ice",
        ObservationSignalKind.Close => "close",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static string? ReadCurrentChannelBindingHex(Func<byte[]> provider)
    {
        byte[] binding = Array.Empty<byte>();
        try
        {
            binding = provider();
            return ObservationAdmissionGrantVerifier.CanonicalChannelBindingHex(binding);
        }
        catch
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(binding);
        }
    }

    private static bool ValidObservationSignal(ObservationSignalKind kind, string payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var bytes = Encoding.UTF8.GetByteCount(payload);
        var maximum = kind switch
        {
            ObservationSignalKind.Challenge => 4096,
            ObservationSignalKind.Offer or ObservationSignalKind.Answer => 65_536,
            ObservationSignalKind.Ice => 4_096,
            ObservationSignalKind.Close => 0,
            _ => -1,
        };
        if (maximum < 0 || bytes > maximum ||
            (kind == ObservationSignalKind.Challenge && bytes == 0) ||
            ((kind is ObservationSignalKind.Offer or ObservationSignalKind.Answer) &&
             (bytes == 0 || !payload.StartsWith("v=0", StringComparison.Ordinal))))
        {
            return false;
        }
        return !payload.Any(character => char.IsControl(character) && character is not ('\r' or '\n' or '\t'));
    }

    private static bool ValidManagerObservationSignal(string kind, string payload)
    {
        ArgumentNullException.ThrowIfNull(kind);
        ArgumentNullException.ThrowIfNull(payload);
        var bytes = Encoding.UTF8.GetByteCount(payload);
        return kind switch
        {
            "offer" => bytes is > 0 and <= 65_536 &&
                       payload.StartsWith("v=0", StringComparison.Ordinal) &&
                       HasSafeObservationSignalText(payload),
            "ice" => bytes is > 0 and <= 4_096 && HasSafeObservationSignalText(payload),
            "close" => bytes == 0,
            _ => false,
        };
    }

    private static bool HasSafeObservationSignalText(string payload) =>
        !payload.Any(character => char.IsControl(character) && character is not ('\r' or '\n' or '\t'));

    private static bool IsCanonicalLowerHex(string value, int byteCount) =>
        value.Length == byteCount * 2 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsToken(string value, int minLength, int maxLength) =>
        value.Length >= minLength && value.Length <= maxLength && value.All(character =>
            character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_');

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsSafeFileName(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value != value.Trim() ||
            Encoding.UTF8.GetByteCount(value) > 255 || value is "." or ".." ||
            value.EndsWith(' ') || value.EndsWith('.') ||
            value.Any(character =>
                character is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*' ||
                char.IsControl(character)))
        {
            return false;
        }

        var deviceStem = value.Split('.', 2)[0].TrimEnd(' ', '.').ToUpperInvariant();
        return deviceStem is not ("CON" or "PRN" or "AUX" or "NUL") &&
            !(deviceStem.Length == 4 &&
              (deviceStem.StartsWith("COM", StringComparison.Ordinal) ||
               deviceStem.StartsWith("LPT", StringComparison.Ordinal)) &&
              deviceStem[3] is >= '1' and <= '9');
    }

    private sealed record FileRequestSessionContext(
        string ComputerId,
        string LocalUserId,
        string LocalUserDisplayName,
        EndpointSession Session);

    private sealed class PreparedUploadSource(
        FileStream stream,
        string fileName,
        ulong fileSizeBytes,
        string sha256) : IDisposable
    {
        public FileStream Stream { get; } = stream;
        public string FileName { get; } = fileName;
        public ulong FileSizeBytes { get; } = fileSizeBytes;
        public string Sha256 { get; } = sha256;
        public string? FileId { get; set; }

        public void Dispose() => Stream.Dispose();
    }

    private static string BuildOutputFileName(string jobId, string originalName)
    {
        var prefix = $"{jobId[..16]}_";
        var output = new StringBuilder(prefix);
        foreach (var rune in originalName.EnumerateRunes())
        {
            if (output.Length + rune.Utf16SequenceLength > 230)
            {
                break;
            }
            output.Append(rune.ToString());
        }
        return output.ToString();
    }

    /// <summary>Creates and returns the per-user received-files folder.</summary>
    public static string GetReceivedFilesDirectory()
    {
        var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localData))
        {
            throw StorageFailure("Windows did not provide a per-user data directory.");
        }

        var root = Path.GetFullPath(localData);
        var helicoid = Path.Combine(root, "Helicoid");
        var computer = Path.Combine(helicoid, "Computer");
        var received = Path.Combine(computer, "Received Files");
        Directory.CreateDirectory(helicoid);
        EnsureDirectoryNotReparsePoint(helicoid);
        Directory.CreateDirectory(computer);
        EnsureDirectoryNotReparsePoint(computer);
        Directory.CreateDirectory(received);
        EnsureDirectoryNotReparsePoint(received);
        return received;
    }

    private static void EnsureDirectoryNotReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if (!attributes.HasFlag(FileAttributes.Directory) || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw StorageFailure("The per-user received-files directory is not a regular local directory.");
        }
    }

    private static bool TryGetAttributes(string path, out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            attributes = default;
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            attributes = default;
            return false;
        }
    }

    private static async Task<bool> MatchesFileAsync(
        string path,
        ulong expectedSize,
        string expectedDigest,
        CancellationToken cancellationToken)
    {
        if (!TryGetAttributes(path, out var attributes) || attributes.HasFlag(FileAttributes.ReparsePoint) ||
            attributes.HasFlag(FileAttributes.Directory))
        {
            return false;
        }

        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if ((ulong)input.Length != expectedSize)
        {
            return false;
        }
        var hash = await SHA256.HashDataAsync(input, cancellationToken).ConfigureAwait(false);
        return string.Equals(Convert.ToHexString(hash).ToLowerInvariant(), expectedDigest, StringComparison.Ordinal);
    }

    private static void TryDeleteOwnedTemporary(string path)
    {
        try
        {
            if (TryGetAttributes(path, out var attributes) &&
                !attributes.HasFlag(FileAttributes.ReparsePoint) &&
                !attributes.HasFlag(FileAttributes.Directory))
            {
                File.Delete(path);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static string GetString(JsonElement element, string propertyName)
    {
        var value = element.GetProperty(propertyName);
        return value.GetString() ?? throw new JsonException("A required string property was null.");
    }

    private static ServerClientException InvalidResponse(string message, Exception? inner = null) =>
        new(ServerClientFailure.InvalidResponse, message, inner);

    private static ServerClientException InvalidObservationGrant() =>
        new(ServerClientFailure.Unauthorized, "The endpoint observation grant is invalid or expired.");

    private static ServerClientException StorageFailure(string message) =>
        new(ServerClientFailure.SecurityStateUnavailable, message);

    public void Dispose()
    {
        lock (_observationAdmissionsLock)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            foreach (var admission in _activeObservationAdmissions.Values)
            {
                admission.Dispose();
            }
            _activeObservationAdmissions.Clear();
            _activeObservationSignals.Clear();
        }
        _pendingObservationAdmissions.Clear();
        _observationGrantExpirations.Clear();
        _transport.Dispose();
    }

    private EndpointEnrollmentConfiguration ReadMatchingEnrollmentConfiguration()
    {
        var configuration = EndpointEnrollmentClient.ReadSavedConfiguration()
            ?? throw StorageFailure(
                "Saved endpoint enrollment trust has no current authority-generation checkpoint. Re-enroll this endpoint through the Manager after recovery review.");
        if (!string.Equals(configuration.Trust.DeploymentId, _trust.DeploymentId, StringComparison.Ordinal) ||
            !string.Equals(configuration.Trust.Origin.AbsoluteUri, _trust.Origin.AbsoluteUri, StringComparison.Ordinal) ||
            !string.Equals(configuration.Trust.CaFingerprintSha256Hex, _trust.CaFingerprintSha256Hex, StringComparison.Ordinal) ||
            !string.Equals(configuration.GrantVerificationPublicKeyHex, _grantVerificationPublicKeyHex, StringComparison.Ordinal) ||
            configuration.AuthorityGeneration != _authorityGeneration)
        {
            throw StorageFailure("The saved endpoint enrollment trust changed.");
        }
        return configuration;
    }

    private async Task VerifyAuthorityCheckpointAsync(CancellationToken cancellationToken)
    {
        var configuration = ReadMatchingEnrollmentConfiguration();
        if (string.IsNullOrEmpty(configuration.GrantVerificationPublicKeyHex) ||
            !IsCanonicalLowerHex(configuration.GrantVerificationPublicKeyHex, 32) ||
            configuration.AuthorityGeneration is not long expectedGeneration || expectedGeneration <= 0)
        {
            throw StorageFailure(
                "This endpoint has no saved authority-generation checkpoint. Re-enroll it through the Manager before using protected operations.");
        }

        var body = await _transport.SendAsync(
            HttpMethod.Get,
            "/v2/deployment/authority",
            content: null,
            cancellationToken,
            expectedStatusCode: 200).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var deploymentId = GetString(root, "deployment_id");
            var publicKey = GetString(root, "grant_signing_public_key");
            long currentGeneration = 0;
            var hasGeneration = root.TryGetProperty("authority_generation", out var generationElement) &&
                generationElement.ValueKind == JsonValueKind.Number &&
                generationElement.TryGetInt64(out currentGeneration) && currentGeneration > 0;
            if (!hasGeneration ||
                !string.Equals(deploymentId, _trust.DeploymentId, StringComparison.Ordinal) ||
                !string.Equals(publicKey, configuration.GrantVerificationPublicKeyHex, StringComparison.Ordinal) ||
                currentGeneration != expectedGeneration)
            {
                await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    _currentSession = null;
                    _currentSessionLocalUserId = null;
                }
                finally
                {
                    _sessionGate.Release();
                }
                lock (_observationAdmissionsLock)
                {
                    foreach (var admission in _activeObservationAdmissions.Values)
                    {
                        admission.Dispose();
                    }
                    _activeObservationAdmissions.Clear();
                    _activeObservationSignals.Clear();
                }
                _pendingObservationAdmissions.Clear();
                _observationGrantExpirations.Clear();
                throw new ServerClientException(
                    ServerClientFailure.SecurityStateUnavailable,
                    "The server authority differs from this endpoint's saved generation. Keep this endpoint quarantined and re-enroll it through the Manager after recovery review.");
            }
        }
        catch (JsonException exception)
        {
            throw InvalidResponse("The deployment authority checkpoint response was invalid.", exception);
        }
        catch (InvalidOperationException exception)
        {
            throw InvalidResponse("The deployment authority checkpoint response was invalid.", exception);
        }
        catch (KeyNotFoundException exception)
        {
            throw InvalidResponse("The deployment authority checkpoint response was incomplete.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    private sealed record EndpointSessionChallengeRequest(
        [property: JsonPropertyName("computer_id")] string ComputerId,
        [property: JsonPropertyName("local_user_id")] string? LocalUserId,
        [property: JsonPropertyName("local_user_display_name")] string? LocalUserDisplayName,
        [property: JsonPropertyName("client_nonce")] string ClientNonce,
        [property: JsonPropertyName("issued_at_unix")] long IssuedAtUnix,
        [property: JsonPropertyName("proof")] string Proof);

    private sealed record EndpointSessionChallenge(
        [property: JsonPropertyName("challenge_id")] string ChallengeId,
        [property: JsonPropertyName("challenge_token")] string ChallengeToken,
        [property: JsonPropertyName("deployment_id")] string DeploymentId,
        [property: JsonPropertyName("computer_id")] string ComputerId,
        [property: JsonPropertyName("enrollment_epoch")] long EnrollmentEpoch,
        [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix);

    private sealed record EndpointSessionCompleteRequest(
        [property: JsonPropertyName("challenge_id")] string ChallengeId,
        [property: JsonPropertyName("challenge_token")] string ChallengeToken,
        [property: JsonPropertyName("signature")] string Signature);

    private sealed record EndpointSession(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("session_id")] string SessionId,
        [property: JsonPropertyName("deployment_id")] string DeploymentId,
        [property: JsonPropertyName("computer_id")] string ComputerId,
        [property: JsonPropertyName("enrollment_epoch")] long EnrollmentEpoch,
        [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix);

    private sealed record RedeemObservationGrantRequest(
        [property: JsonPropertyName("grant_token")] string GrantToken,
        [property: JsonPropertyName("endpoint_nonce")] string EndpointNonce,
        [property: JsonPropertyName("channel_binding")] string ChannelBinding,
        [property: JsonPropertyName("manager_proof")] string ManagerProof);

    private sealed record ObservationSignalRequest(
        [property: JsonPropertyName("kind")] string Kind,
        [property: JsonPropertyName("payload")] string Payload);

    private sealed record EndpointPendingObservationGrants(
        [property: JsonPropertyName("grants")] List<EndpointPendingObservationGrant>? Grants);

    private sealed record EndpointPendingObservationGrant(
        [property: JsonPropertyName("grant_id")] string GrantId,
        [property: JsonPropertyName("computer_id")] string ComputerId,
        [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix,
        [property: JsonPropertyName("grant_token")] string GrantToken);

    private sealed record ObservationAdmissionAcceptedResponse(
        [property: JsonPropertyName("grant_id")] string GrantId,
        [property: JsonPropertyName("computer_id")] string ComputerId,
        [property: JsonPropertyName("endpoint_session_id")] string EndpointSessionId,
        [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix);

    private sealed record PendingObservationAdmission(
        string GrantToken,
        VerifiedObservationAdmissionGrant Grant,
        ObservationAdmissionChallenge Challenge,
        EndpointEnrollmentResult Enrollment,
        string LocalUserId,
        EndpointSession Session);

    private sealed record ActiveObservationSignalContext(
        string GrantId,
        long ExpiresAtUnix,
        string LocalUserId,
        EndpointEnrollmentResult Enrollment,
        EndpointSession Session);

    private sealed record EndpointFileJobList(
        [property: JsonPropertyName("jobs")] List<EndpointFileJob>? Jobs);

    private sealed record EndpointFileJob(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("file_name")] string FileName,
        [property: JsonPropertyName("file_size_bytes")] ulong FileSizeBytes,
        [property: JsonPropertyName("sha256")] string Sha256,
        [property: JsonPropertyName("chunk_size_bytes")] uint ChunkSizeBytes,
        [property: JsonPropertyName("chunk_count")] uint ChunkCount,
        [property: JsonPropertyName("state")] string State);

    private sealed record EndpointFileJobResult(
        [property: JsonPropertyName("succeeded")] bool Succeeded,
        [property: JsonPropertyName("detail")] string? Detail,
        [property: JsonPropertyName("received_size_bytes")] ulong? ReceivedSizeBytes,
        [property: JsonPropertyName("received_sha256")] string? ReceivedSha256);

    private sealed record EndpointFileRequestListResponse(
        [property: JsonPropertyName("requests")] List<EndpointFileRequestDto>? Requests,
        [property: JsonPropertyName("max_page_size")] int MaxPageSize);

    private sealed record EndpointFileRequestDto(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("revision")] long Revision,
        [property: JsonPropertyName("title")] string Title,
        [property: JsonPropertyName("instructions")] string Instructions,
        [property: JsonPropertyName("allowed_extensions")] List<string>? AllowedExtensions,
        [property: JsonPropertyName("max_file_count")] uint MaxFileCount,
        [property: JsonPropertyName("max_total_size_bytes")] ulong MaxTotalSizeBytes,
        [property: JsonPropertyName("closes_at_unix")] long ClosesAtUnix,
        [property: JsonPropertyName("replacement_allowed")] bool ReplacementAllowed);

    private sealed record EndpointFileRequestSubmissionDto(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("request_id")] string RequestId,
        [property: JsonPropertyName("request_revision")] long RequestRevision,
        [property: JsonPropertyName("computer_id")] string ComputerId,
        [property: JsonPropertyName("local_user_display_name")] string LocalUserDisplayName,
        [property: JsonPropertyName("state")] string State,
        [property: JsonPropertyName("created_at_unix")] long CreatedAtUnix,
        [property: JsonPropertyName("replaces_submission_id")] string? ReplacesSubmissionId,
        [property: JsonPropertyName("files")] List<EndpointFileRequestSubmissionFileDto>? Files);

    private sealed record EndpointFileRequestSubmissionFileDto(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("file_name")] string FileName,
        [property: JsonPropertyName("file_size_bytes")] ulong FileSizeBytes,
        [property: JsonPropertyName("sha256")] string Sha256,
        [property: JsonPropertyName("chunk_size_bytes")] uint ChunkSizeBytes,
        [property: JsonPropertyName("chunk_count")] uint ChunkCount,
        [property: JsonPropertyName("state")] string State);

    private sealed record FileRequestSubmissionFileManifest(
        [property: JsonPropertyName("file_name")] string FileName,
        [property: JsonPropertyName("file_size_bytes")] ulong FileSizeBytes,
        [property: JsonPropertyName("sha256")] string Sha256);

    private sealed record CreateFileRequestSubmissionRequest(
        [property: JsonPropertyName("request_revision")] long RequestRevision,
        [property: JsonPropertyName("files")] List<FileRequestSubmissionFileManifest> Files,
        [property: JsonPropertyName("replace_submission_id")] string? ReplaceSubmissionId,
        [property: JsonPropertyName("confirm_replacement")] bool ConfirmReplacement);

    private sealed record CompleteFileRequestSubmissionRequest(
        [property: JsonPropertyName("request_revision")] long RequestRevision,
        [property: JsonPropertyName("confirm_submission_id")] string ConfirmSubmissionId);

    private sealed record EndpointFileRequestChunkReceipt(
        [property: JsonPropertyName("submission_id")] string SubmissionId,
        [property: JsonPropertyName("file_id")] string FileId,
        [property: JsonPropertyName("chunk_index")] uint ChunkIndex,
        [property: JsonPropertyName("sha256")] string Sha256);

    private sealed class EndpointFileDeliveryFailureException(string message) : Exception(message);
    private sealed class EndpointFileDeliveryPausedException(string message) : Exception(message);
}
