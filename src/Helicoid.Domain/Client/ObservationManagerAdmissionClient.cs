using System.Security.Cryptography;
using System.Text.Json;

namespace Helicoid.Domain.Client;

/// <summary>
/// Non-secret identity captured when one v2 Manager session was installed.
/// The generation is the client's session fence; IDs come only from the
/// validated completion response, never from an observation response.
/// </summary>
internal sealed record ObservationManagerSessionIdentity(
    string DeploymentId,
    string AccountId,
    string ManagerId,
    string ManagerPublicKeyHex,
    int SessionGeneration);

/// <summary>
/// PREPARATORY-ONLY: an in-memory deployment authority tuple supplied by a
/// future verified, persisted Manager checkpoint. This checkout has no such
/// Manager checkpoint storage, so observation admission must not be connected
/// to production. A caller must not obtain these values from a network
/// response or an unverified health read.
/// </summary>
internal sealed class ObservationAuthorityCheckpoint
{
    private ObservationAuthorityCheckpoint(
        string deploymentId,
        string grantSigningPublicKeyHex,
        long authorityGeneration)
    {
        DeploymentId = deploymentId;
        GrantSigningPublicKeyHex = grantSigningPublicKeyHex;
        AuthorityGeneration = authorityGeneration;
    }

    public string DeploymentId { get; }
    public string GrantSigningPublicKeyHex { get; }
    public long AuthorityGeneration { get; }

    internal static ObservationAuthorityCheckpoint Create(
        string deploymentId,
        string grantSigningPublicKeyHex,
        long authorityGeneration)
    {
        if (!ObservationAdmissionGrantVerifier.IsCanonicalDeploymentId(deploymentId) ||
            !ObservationAdmissionGrantVerifier.IsLowerHex(grantSigningPublicKeyHex, 32) ||
            authorityGeneration <= 0)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "The deployment authority checkpoint is invalid.");
        }

        return new ObservationAuthorityCheckpoint(
            deploymentId,
            grantSigningPublicKeyHex,
            authorityGeneration);
    }
}

/// <summary>
/// A server-signed observation grant that was verified against the exact
/// Manager session and computer that requested it. The admission cannot be
/// reused by a replacement session or another device key.
/// </summary>
internal sealed class ObservationManagerAdmission
{
    private readonly object _gate = new();
    private long _lastCursor;
    private bool _pollInFlight;
    private bool _challengeAccepted;

    internal ObservationManagerAdmission(
        VerifiedObservationAdmissionGrant grant,
        ObservationManagerSessionIdentity session)
    {
        Grant = grant;
        Session = session;
    }

    public VerifiedObservationAdmissionGrant Grant { get; }

    internal ObservationManagerSessionIdentity Session { get; }

    /// <summary>
    /// Reserve one poll. A caller may not move backwards, overlap polls, or
    /// poll again after a certificate-attested challenge was accepted.
    /// </summary>
    internal void BeginPoll(long afterCursor)
    {
        lock (_gate)
        {
            if (_challengeAccepted)
            {
                throw new ServerClientException(
                    ServerClientFailure.Unauthorized,
                    "The observation admission already consumed its endpoint challenge.");
            }

            if (_pollInFlight)
            {
                throw new ServerClientException(
                    ServerClientFailure.Conflict,
                    "An observation challenge poll is already in flight.");
            }

            if (afterCursor < _lastCursor)
            {
                throw new ServerClientException(
                    ServerClientFailure.BadRequest,
                    "The observation signaling cursor cannot move backwards.");
            }

            _pollInFlight = true;
        }
    }

    internal void CompletePoll(long cursor, bool challengeAccepted)
    {
        lock (_gate)
        {
            _lastCursor = Math.Max(_lastCursor, cursor);
            _challengeAccepted = challengeAccepted;
            _pollInFlight = false;
        }
    }

    internal void AbortPoll()
    {
        lock (_gate)
        {
            _pollInFlight = false;
        }
    }
}

/// <summary>One bounded signal poll result and its verified endpoint challenge.</summary>
internal sealed record ObservationChallengePoll(
    long Cursor,
    VerifiedObservationEndpointChallenge? Challenge);

/// <summary>
/// PREPARATORY-ONLY Manager admission seam for live observation. It is
/// internal because this checkout has no verified, persisted Manager
/// deployment-authority checkpoint. It can request a one-use server-signed
/// grant over an authenticated pinned v2 session, verify the grant against
/// the signed-in account, Manager, device key, deployment, and exact computer,
/// then read only the endpoint's certificate-attested challenge signal.
///
/// This type stops before any native peer, offer, capture, or input path. A
/// verified challenge is not a live preview and grants no remote control.
/// Response byte buffers are zeroed after parsing. Intermediate managed
/// strings, including the grant token, cannot be zeroized.
/// </summary>
internal sealed class ObservationManagerAdmissionClient
{
    private const int MaximumGrantResponseBytes = 16 * 1024;
    private const int MaximumSignalResponseBytes = 16 * 1024;
    private const int MaximumGrantTokenBytes = 8 * 1024;
    private const int MaximumChallengeBytes = 4 * 1024;
    private const int MaximumSignalBatchMessages = 64;
    private const long MaximumSignalCursor = 128;

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 4,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
    };

    private readonly V2DeviceKeyChallengeClient _session;
    private readonly ObservationAuthorityCheckpoint _authority;
    private readonly TimeProvider _timeProvider;

    internal ObservationManagerAdmissionClient(
        V2DeviceKeyChallengeClient session,
        ObservationAuthorityCheckpoint authority,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _session = session;
        _authority = authority;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Request one short-lived observation grant for an exact computer. The
    /// server must return 201 with the four documented fields, and the signed
    /// token must match this live Manager session before the admission is
    /// returned.
    /// </summary>
    internal async Task<ObservationManagerAdmission> RequestGrantAsync(
        string computerId,
        CancellationToken cancellationToken)
    {
        if (!ObservationAdmissionGrantVerifier.IsCanonicalUuid(computerId))
        {
            throw new ServerClientException(
                ServerClientFailure.BadRequest,
                "The observation computer id is not a canonical UUID.");
        }

        ObservationManagerSessionIdentity session = RequireSession();
        RequireAuthority(session);
        string payload = JsonSerializer.Serialize(new { computer_id = computerId });
        byte[] body = await _session.SendAuthorizedJsonAsync(
                HttpMethod.Post,
                "/v2/admissions/observation",
                payload,
                expectedStatusCode: 201,
                expectedSessionGeneration: session.SessionGeneration,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        try
        {
            ObservationManagerAdmission admission = ParseGrantResponse(body, computerId, session);
            // Re-fence after parsing: a replacement session must not inherit
            // an admission that was verified under the previous generation.
            RequireCurrentSession(admission);
            return admission;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>
    /// Poll the grant-scoped Manager signaling mailbox at or after
    /// <paramref name="afterCursor"/>. Only one endpoint certificate-attested
    /// challenge is accepted. The returned cursor is the server cursor for the
    /// next poll; an empty poll has a null challenge. Once a challenge is
    /// accepted, this admission is consumed: later polls are rejected and the
    /// caller must request a fresh grant. The cursor never moves backwards.
    /// </summary>
    internal async Task<ObservationChallengePoll> PollChallengeAsync(
        ObservationManagerAdmission admission,
        long afterCursor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(admission);
        if (afterCursor < 0 || afterCursor > MaximumSignalCursor)
        {
            throw new ServerClientException(
                ServerClientFailure.BadRequest,
                "The observation signaling cursor is out of range.");
        }

        admission.BeginPoll(afterCursor);
        try
        {
            ObservationManagerSessionIdentity session = RequireCurrentSession(admission);
            if (admission.Grant.ExpiresAtUnix <= _timeProvider.GetUtcNow().ToUnixTimeSeconds())
            {
                throw new ServerClientException(
                    ServerClientFailure.Unauthorized,
                    "The observation admission expired before signaling was read.");
            }

            string path = FormattableString.Invariant(
                $"/v2/admissions/observation/{admission.Grant.GrantId}/signals?after={afterCursor}");
            byte[] body = await _session.SendAuthorizedJsonAsync(
                    HttpMethod.Get,
                    path,
                    payload: null,
                    expectedStatusCode: 200,
                    expectedSessionGeneration: session.SessionGeneration,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            try
            {
                ObservationChallengePoll poll = ParseSignalBatch(
                    body,
                    admission,
                    session,
                    afterCursor);
                admission.CompletePoll(poll.Cursor, poll.Challenge is not null);
                return poll;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
        catch
        {
            admission.AbortPoll();
            throw;
        }
    }

    private ObservationManagerSessionIdentity RequireSession()
    {
        ObservationManagerSessionIdentity? identity = _session.TryGetObservationSessionIdentity();
        if (identity is null)
        {
            if (!_session.IsSessionLive)
            {
                throw new ServerClientException(
                    ServerClientFailure.NotConnected,
                    "No active Manager session. Sign in before requesting observation.");
            }

            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The Manager session identity is incomplete for observation.");
        }

        if (!ObservationAdmissionGrantVerifier.IsCanonicalUuid(identity.AccountId) ||
            !ObservationAdmissionGrantVerifier.IsCanonicalUuid(identity.ManagerId) ||
            !ObservationAdmissionGrantVerifier.IsLowerHex(identity.ManagerPublicKeyHex, 32) ||
            !string.Equals(identity.ManagerPublicKeyHex, _session.DeviceKey.PublicKeyHex, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The Manager session identity is not valid for observation.");
        }

        return identity;
    }

    private void RequireAuthority(ObservationManagerSessionIdentity session)
    {
        if (!string.Equals(
                _authority.DeploymentId,
                session.DeploymentId,
                StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The deployment authority checkpoint does not match this Manager session.");
        }
    }

    private ObservationManagerSessionIdentity RequireCurrentSession(
        ObservationManagerAdmission admission)
    {
        ObservationManagerSessionIdentity identity = RequireSession();
        RequireAuthority(identity);
        if (identity.SessionGeneration != admission.Session.SessionGeneration ||
            !string.Equals(identity.DeploymentId, admission.Session.DeploymentId, StringComparison.Ordinal) ||
            !string.Equals(identity.AccountId, admission.Session.AccountId, StringComparison.Ordinal) ||
            !string.Equals(identity.ManagerId, admission.Session.ManagerId, StringComparison.Ordinal) ||
            !string.Equals(
                identity.ManagerPublicKeyHex,
                admission.Session.ManagerPublicKeyHex,
                StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The observation admission belongs to another Manager session.");
        }

        return identity;
    }

    private ObservationManagerAdmission ParseGrantResponse(
        byte[] body,
        string computerId,
        ObservationManagerSessionIdentity session)
    {
        using JsonDocument document = ParseObject(body, MaximumGrantResponseBytes);
        Dictionary<string, JsonElement> values = ExactProperties(
            document.RootElement,
            "grant_id",
            "computer_id",
            "expires_at_unix",
            "grant_token");

        string grantId = ReadString(values, "grant_id");
        string responseComputerId = ReadString(values, "computer_id");
        long expiresAtUnix = ReadInteger(values, "expires_at_unix");
        string grantToken = ReadString(values, "grant_token");

        long nowUnix = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (!ObservationAdmissionGrantVerifier.IsCanonicalUuid(grantId) ||
            !string.Equals(responseComputerId, computerId, StringComparison.Ordinal) ||
            expiresAtUnix <= nowUnix ||
            expiresAtUnix > nowUnix +
                ObservationAdmissionGrantVerifier.MaximumLifetimeSeconds +
                ObservationAdmissionGrantVerifier.MaximumClockSkewSeconds ||
            grantToken.Length is 0 or > MaximumGrantTokenBytes ||
            grantToken.Any(static character => character > 0x7f || character == '\0'))
        {
            throw InvalidResponse("The server returned an invalid observation grant response.");
        }

        var expected = new ObservationAdmissionManager(
            session.DeploymentId,
            session.AccountId,
            computerId,
            session.ManagerId,
            session.ManagerPublicKeyHex);
        VerifiedObservationAdmissionGrant grant = ObservationAdmissionGrantVerifier.VerifyForManager(
            grantToken,
            _authority.GrantSigningPublicKeyHex,
            expected,
            _timeProvider.GetUtcNow());

        if (!string.Equals(grant.GrantId, grantId, StringComparison.Ordinal) ||
            !string.Equals(grant.ComputerId, computerId, StringComparison.Ordinal) ||
            grant.ExpiresAtUnix != expiresAtUnix)
        {
            throw InvalidResponse("The observation grant response does not match its signed claims.");
        }

        return new ObservationManagerAdmission(grant, session);
    }

    private ObservationChallengePoll ParseSignalBatch(
        byte[] body,
        ObservationManagerAdmission admission,
        ObservationManagerSessionIdentity session,
        long afterCursor)
    {
        long nowUnix = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        using JsonDocument document = ParseObject(body, MaximumSignalResponseBytes);
        Dictionary<string, JsonElement> values = ExactProperties(
            document.RootElement,
            "cursor",
            "messages");

        long cursor = ReadInteger(values, "cursor");
        JsonElement messages = values["messages"];
        if (cursor < afterCursor ||
            cursor > MaximumSignalCursor ||
            messages.ValueKind != JsonValueKind.Array ||
            messages.GetArrayLength() > MaximumSignalBatchMessages)
        {
            throw InvalidResponse("The observation signaling response is invalid.");
        }

        long lastSequence = afterCursor;
        VerifiedObservationEndpointChallenge? challenge = null;
        foreach (JsonElement message in messages.EnumerateArray())
        {
            if (message.ValueKind != JsonValueKind.Object)
            {
                throw InvalidResponse("The endpoint sent an invalid observation challenge signal.");
            }

            Dictionary<string, JsonElement> fields = ExactProperties(
                message,
                "sequence",
                "sender",
                "kind",
                "payload");
            long sequence = ReadInteger(fields, "sequence");
            string sender = ReadString(fields, "sender");
            string kind = ReadString(fields, "kind");
            string payload = ReadString(fields, "payload");

            // The Manager may only consume endpoint challenges before any
            // offer. A manager-echoed, reordered, duplicate, or non-challenge
            // signal is refused rather than guessed at.
            if (sequence <= lastSequence ||
                sequence > cursor ||
                sequence > MaximumSignalCursor ||
                !string.Equals(sender, "endpoint", StringComparison.Ordinal) ||
                !string.Equals(kind, "challenge", StringComparison.Ordinal) ||
                payload.Length is 0 or > MaximumChallengeBytes ||
                challenge is not null)
            {
                throw InvalidResponse("The endpoint sent an invalid observation challenge signal.");
            }

            lastSequence = sequence;
            challenge = ObservationEndpointChallenge.Verify(
                payload,
                admission.Grant,
                DateTimeOffset.FromUnixTimeSeconds(nowUnix));
        }

        // The exact caller session and device identity must still own the
        // verified grant after parsing and signature work.
        ObservationManagerSessionIdentity current = RequireCurrentSession(admission);
        if (current.SessionGeneration != session.SessionGeneration)
        {
            throw new ServerClientException(
                ServerClientFailure.Unauthorized,
                "The observation admission belongs to another Manager session.");
        }

        return new ObservationChallengePoll(cursor, challenge);
    }

    private static JsonDocument ParseObject(byte[] body, int maximumBytes)
    {
        if (body.Length is 0 || body.Length > maximumBytes)
        {
            throw InvalidResponse("The observation response exceeded its bound.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body, DocumentOptions);
        }
        catch (JsonException)
        {
            throw InvalidResponse("The observation response was not valid JSON.");
        }

        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw InvalidResponse("The observation response was not an object.");
        }

        return document;
    }

    private static Dictionary<string, JsonElement> ExactProperties(
        JsonElement value,
        params string[] names)
    {
        var expected = new HashSet<string>(names, StringComparer.Ordinal);
        var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (JsonProperty property in value.EnumerateObject())
        {
            if (!expected.Contains(property.Name) || !values.TryAdd(property.Name, property.Value))
            {
                throw InvalidResponse("The observation response contained an unexpected or duplicate field.");
            }
        }

        if (values.Count != expected.Count)
        {
            throw InvalidResponse("The observation response was missing a required field.");
        }

        return values;
    }

    private static string ReadString(Dictionary<string, JsonElement> values, string name)
    {
        JsonElement value = values[name];
        if (value.ValueKind != JsonValueKind.String)
        {
            throw InvalidResponse("The observation response field had the wrong type.");
        }

        return value.GetString() ?? throw InvalidResponse(
            "The observation response field had no value.");
    }

    private static long ReadInteger(Dictionary<string, JsonElement> values, string name)
    {
        JsonElement value = values[name];
        if (value.ValueKind != JsonValueKind.Number ||
            value.GetRawText().Any(static character => character is '.' or 'e' or 'E') ||
            !value.TryGetInt64(out long result))
        {
            throw InvalidResponse("The observation response field was not an integer.");
        }

        return result;
    }

    private static ServerClientException InvalidResponse(string message) => new(
        ServerClientFailure.InvalidResponse,
        message);
}
