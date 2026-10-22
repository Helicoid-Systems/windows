using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Helicoid.Domain.Client;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Redeems a one-time Manager invitation and records a pending endpoint
/// identity. Enrollment alone grants no observation, capture, or input access.
/// </summary>
public sealed class EndpointEnrollmentClient : IDisposable
{
    private const int MaxResponseBytes = 16 * 1024;
    private const string EnrollmentPath = "/v2/endpoints/enroll";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly DeploymentTlsTrust _trust;
    private readonly PinnedHttpsTransport _transport;
    private readonly string _storageDirectory;

    public EndpointEnrollmentClient(DeploymentTlsTrust trust)
    {
        ArgumentNullException.ThrowIfNull(trust);
        _trust = trust;
        _storageDirectory = GetStorageDirectory();
        _transport = new PinnedHttpsTransport(
            trust,
            PinnedHttpsTransport.DefaultTimeout,
            MaxResponseBytes);
    }

    /// <summary>
    /// Redeems a canonical invitation over the origin and CA pinned in
    /// this endpoint client's deployment trust. The invitation code is sent
    /// once and never stored; a successful response is persisted only as
    /// DPAPI-protected pending-enrollment metadata.
    /// </summary>
    public async Task<EndpointEnrollmentResult> EnrollAsync(
        string invitationId,
        string enrollmentCode,
        CancellationToken cancellationToken)
    {
        ValidateInvitation(invitationId, enrollmentCode);
        cancellationToken.ThrowIfCancellationRequested();

        using var enrollmentStorage = new EnrollmentStorage(_storageDirectory);
        if (enrollmentStorage.Exists())
        {
            return ReadStoredEnrollment(enrollmentStorage, _trust.DeploymentId);
        }

        using var keyStorage = new DeviceKeyStorage(_storageDirectory);
        var storageResult = keyStorage.OpenOrCreate(out var seed, out var storedPublicKey);
        try
        {
            if (storageResult != DeviceKeyStorageResult.Success)
            {
                throw StorageFailure("The protected endpoint identity could not be opened or created.");
            }

            using var signingKey = Ed25519DeviceKey.ImportSeed(seed);
            if (!Ed25519DeviceKey.TryParsePublicKey(signingKey.PublicKeyHex, out var derivedPublicKey))
            {
                throw StorageFailure("The protected endpoint identity is invalid. It was not replaced.");
            }

            try
            {
                if (storedPublicKey.Length != derivedPublicKey.Length ||
                    !CryptographicOperations.FixedTimeEquals(storedPublicKey, derivedPublicKey))
                {
                    throw StorageFailure("The protected endpoint identity is inconsistent. It was not replaced.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedPublicKey);
            }

            var codeBytes = Encoding.UTF8.GetBytes(enrollmentCode);
            var codeHashBytes = SHA256.HashData(codeBytes);
            var message = Encoding.UTF8.GetBytes(
                $"hs-endpoint-enroll-v2|deployment:{_trust.DeploymentId}|invitation:{invitationId}|code_hash:{Ed25519DeviceKey.ToLowerHex(codeHashBytes)}|endpoint:{signingKey.PublicKeyHex}");
            byte[]? proof = null;
            byte[]? body = null;
            try
            {
                proof = signingKey.Sign(message);
                body = JsonSerializer.SerializeToUtf8Bytes(
                    new EndpointEnrollmentRequest(
                        invitationId,
                        enrollmentCode,
                        signingKey.PublicKeyHex,
                        Ed25519DeviceKey.ToLowerHex(proof)),
                    JsonOptions);

                using var content = new ByteArrayContent(body);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                byte[] response;
                try
                {
                    response = await _transport.SendAsync(
                        HttpMethod.Post,
                        EnrollmentPath,
                        content,
                        cancellationToken,
                        expectedStatusCode: 201).ConfigureAwait(false);
                }
                catch (ServerClientException exception) when (
                    exception.HttpStatus == 401 || exception.Failure == ServerClientFailure.Unauthorized)
                {
                    throw new ServerClientException(
                        ServerClientFailure.Unauthorized,
                        "The invitation was rejected, expired, revoked, or already used. Ask the Manager for a new invitation.",
                        exception)
                    {
                        HttpStatus = 401,
                    };
                }
                catch (ServerClientException exception) when (
                    exception.Failure is ServerClientFailure.Timeout or ServerClientFailure.TransportFailed)
                {
                    throw new ServerClientException(
                        exception.Failure,
                        "The server connection ended before enrollment could be confirmed. The invitation may have been accepted; ask the Manager to inspect this computer before retrying.",
                        exception);
                }
                catch (ServerClientException exception) when (exception.HttpStatus is >= 200 and < 300)
                {
                    throw new ServerClientException(
                        ServerClientFailure.InvalidResponse,
                        "The server returned an unexpected enrollment response. The invitation may have been accepted; ask the Manager to inspect this computer before retrying.",
                        exception)
                    {
                        HttpStatus = exception.HttpStatus,
                    };
                }

                EndpointEnrollmentResult result;
                try
                {
                    result = ParseAcceptedResponse(response);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(response);
                }
                DeploymentAuthorityCheckpoint authority;
                try
                {
                    authority = await FetchDeploymentAuthorityAsync(
                        cancellationToken).ConfigureAwait(false);
                }
                catch (ServerClientException exception)
                {
                    throw new ServerClientException(
                        exception.Failure,
                        "The server accepted the invitation, but its authority checkpoint could not be pinned. Ask the Manager to inspect this computer before retrying.",
                        exception)
                    {
                        HttpStatus = exception.HttpStatus,
                    };
                }
                var caDer = _trust.CopyCaDer();
                byte[] stored;
                try
                {
                    stored = JsonSerializer.SerializeToUtf8Bytes(
                        new StoredEndpointEnrollment(
                            4,
                            _trust.DeploymentId,
                            result,
                            _trust.Origin.AbsoluteUri,
                            Convert.ToBase64String(caDer),
                            _trust.CaFingerprintSha256Hex,
                            authority.GrantVerificationPublicKeyHex,
                            authority.AuthorityGeneration),
                        JsonOptions);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(caDer);
                }
                try
                {
                    var saveResult = enrollmentStorage.Create(stored);
                    if (saveResult != EnrollmentStorageResult.Success)
                    {
                        if (saveResult == EnrollmentStorageResult.AlreadyExists &&
                            ReadStoredEnrollment(enrollmentStorage, _trust.DeploymentId) == result)
                        {
                            return result;
                        }

                        throw new ServerClientException(
                            ServerClientFailure.SecurityStateUnavailable,
                            "The server accepted the invitation, but pending-enrollment details could not be saved. Ask the Manager to inspect this computer before retrying.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(stored);
                }

                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(codeBytes);
                CryptographicOperations.ZeroMemory(codeHashBytes);
                CryptographicOperations.ZeroMemory(message);
                if (proof is not null)
                {
                    CryptographicOperations.ZeroMemory(proof);
                }

                if (body is not null)
                {
                    CryptographicOperations.ZeroMemory(body);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(storedPublicKey);
        }
    }

    private static void ValidateInvitation(string invitationId, string enrollmentCode)
    {
        if (invitationId.Length != 36 ||
            !Guid.TryParseExact(invitationId, "D", out var parsed) ||
            !string.Equals(parsed.ToString("D"), invitationId, StringComparison.Ordinal))
        {
            throw new ServerClientException(
                ServerClientFailure.BadRequest,
                "Invitation ID must be a canonical lowercase UUID.");
        }

        if (enrollmentCode.Length != 43 || enrollmentCode.Any(character =>
                !((character is >= 'A' and <= 'Z') ||
                  (character is >= 'a' and <= 'z') ||
                  (character is >= '0' and <= '9') || character is '-' or '_')))
        {
            throw new ServerClientException(
                ServerClientFailure.BadRequest,
                "The one-time code must contain 43 letters, digits, underscores, or hyphens.");
        }
    }

    private async Task<DeploymentAuthorityCheckpoint> FetchDeploymentAuthorityAsync(
        CancellationToken cancellationToken)
    {
        byte[] body = await _transport.GetAsync(
            "/v2/deployment/authority",
            cancellationToken).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var deploymentId = GetString(root, "deployment_id");
            var publicKey = GetString(root, "grant_signing_public_key");
            if (!root.TryGetProperty("authority_generation", out var generationElement) ||
                generationElement.ValueKind != JsonValueKind.Number ||
                !generationElement.TryGetInt64(out var authorityGeneration) || authorityGeneration <= 0)
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "The authority response has no valid generation checkpoint.");
            }
            if (!string.Equals(deploymentId, _trust.DeploymentId, StringComparison.Ordinal) ||
                !IsCanonicalLowerHex(publicKey, 32))
            {
                throw new ServerClientException(
                    ServerClientFailure.InvalidResponse,
                    "The authority response does not match this deployment.");
            }
            return new DeploymentAuthorityCheckpoint(publicKey, authorityGeneration);
        }
        catch (JsonException exception)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "The deployment returned invalid grant-verification details.",
                exception);
        }
        catch (InvalidOperationException exception)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "The deployment returned invalid grant-verification details.",
                exception);
        }
        catch (KeyNotFoundException exception)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "The deployment returned incomplete grant-verification details.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    private EndpointEnrollmentResult ParseAcceptedResponse(byte[] response)
    {
        try
        {
            using var document = JsonDocument.Parse(response);
            var root = document.RootElement;
            var computer = root.GetProperty("computer");
            var result = new EndpointEnrollmentResult(
                GetString(computer, "id"),
                GetString(computer, "friendly_name"),
                GetString(computer, "platform"),
                GetString(computer, "enrollment_state"),
                computer.GetProperty("enrollment_epoch").GetInt32());

            if (!string.Equals(GetString(root, "state"), "pending_approval", StringComparison.Ordinal) ||
                !Guid.TryParseExact(result.ComputerId, "D", out var computerId) ||
                !string.Equals(computerId.ToString("D"), result.ComputerId, StringComparison.Ordinal) ||
                !string.Equals(result.Platform, "windows", StringComparison.Ordinal) ||
                !string.Equals(result.EnrollmentState, "pending", StringComparison.Ordinal) ||
                result.EnrollmentEpoch != 1 ||
                string.IsNullOrWhiteSpace(result.FriendlyName) ||
                result.FriendlyName.Length > 128 ||
                result.FriendlyName.Any(char.IsControl))
            {
                throw InvalidAcceptedResponse();
            }

            return result;
        }
        catch (JsonException exception)
        {
            throw InvalidAcceptedResponse(exception);
        }
        catch (InvalidOperationException exception)
        {
            throw InvalidAcceptedResponse(exception);
        }
        catch (KeyNotFoundException exception)
        {
            throw InvalidAcceptedResponse(exception);
        }
        catch (FormatException exception)
        {
            throw InvalidAcceptedResponse(exception);
        }
    }

    private static string GetString(JsonElement value, string propertyName)
    {
        var property = value.GetProperty(propertyName);
        return property.GetString() ?? throw new JsonException("A required string property was null.");
    }

    private static EndpointEnrollmentResult ReadStoredEnrollment(
        EnrollmentStorage storage,
        string? deploymentId)
    {
        var result = storage.Open(out var bytes);
        try
        {
            if (result != EnrollmentStorageResult.Success || bytes is null)
            {
                throw StorageFailure("Saved endpoint enrollment state could not be read. It was not replaced.");
            }

            var stored = JsonSerializer.Deserialize<StoredEndpointEnrollment>(bytes, JsonOptions);
            if (stored is null || stored.Version is not (1 or 2 or 3 or 4) ||
                !IsValidDeploymentId(stored.DeploymentId) ||
                stored.Computer is null ||
                !IsValidStoredResult(stored.Computer))
            {
                throw StorageFailure("Saved endpoint enrollment state is invalid. It was not replaced.");
            }

            if (deploymentId is not null &&
                !string.Equals(stored.DeploymentId, deploymentId, StringComparison.Ordinal))
            {
                throw new ServerClientException(
                    ServerClientFailure.Conflict,
                    "This Windows Computer installation already has an endpoint identity for another deployment.");
            }

            return stored.Computer;
        }
        catch (JsonException exception)
        {
            throw StorageFailure("Saved endpoint enrollment state is invalid. It was not replaced.", exception);
        }
        finally
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    private static bool IsValidStoredResult(EndpointEnrollmentResult value) =>
        Guid.TryParseExact(value.ComputerId, "D", out var id) &&
        string.Equals(id.ToString("D"), value.ComputerId, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(value.FriendlyName) &&
        value.FriendlyName.Length <= 128 &&
        !value.FriendlyName.Any(char.IsControl) &&
        string.Equals(value.Platform, "windows", StringComparison.Ordinal) &&
        string.Equals(value.EnrollmentState, "pending", StringComparison.Ordinal) &&
        value.EnrollmentEpoch == 1;

    private static bool IsValidDeploymentId(string? deploymentId) =>
        !string.IsNullOrWhiteSpace(deploymentId) &&
        deploymentId.Length <= DeploymentTlsTrust.MaxDeploymentIdLength &&
        string.Equals(deploymentId, deploymentId.Trim(), StringComparison.Ordinal) &&
        !deploymentId.Any(char.IsControl);

    private static bool IsCanonicalLowerHex(string? value, int byteCount) =>
        value is not null && value.Length == byteCount * 2 && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static ServerClientException InvalidAcceptedResponse(Exception? inner = null) =>
        new(
            ServerClientFailure.InvalidResponse,
            "The server accepted the invitation but returned invalid enrollment details. Ask the Manager to inspect the pending computer before retrying.",
            inner);

    private static ServerClientException StorageFailure(string message, Exception? inner = null) =>
        new(ServerClientFailure.SecurityStateUnavailable, message, inner);

    /// <summary>
    /// Loads the last accepted enrollment response from protected local state.
    /// This is an enrollment receipt only; it does not prove current server
    /// connectivity, approval, capture, or authorization.
    /// </summary>
    public static EndpointEnrollmentResult? ReadSavedEnrollment()
    {
        var directory = GetStorageDirectory();
        using var storage = new EnrollmentStorage(directory);
        if (!storage.Exists())
        {
            return null;
        }

        return ReadStoredEnrollment(storage, deploymentId: null);
    }

    /// <summary>Whether either protected enrollment metadata or its device key remains.</summary>
    public static bool HasSavedLocalIdentity()
    {
        var directory = GetStorageDirectory();
        using var enrollmentStorage = new EnrollmentStorage(directory);
        using var keyStorage = new DeviceKeyStorage(directory);
        return enrollmentStorage.Exists() || keyStorage.Exists();
    }

    /// <summary>
    /// Explicitly forget local identity state. Delete the device key first so
    /// enrollment metadata is retained if key deletion fails; retries are
    /// idempotent. Received files are stored separately and are not removed.
    /// </summary>
    public static void ForgetSavedIdentity()
    {
        var directory = GetStorageDirectory();
        using (var keyStorage = new DeviceKeyStorage(directory))
        {
            var result = keyStorage.Forget();
            if (result is not (DeviceKeyStorageResult.Forgotten or DeviceKeyStorageResult.NotFound))
            {
                throw StorageFailure("The protected endpoint signing key could not be forgotten. Enrollment metadata was retained.");
            }
        }

        using (var enrollmentStorage = new EnrollmentStorage(directory))
        {
            var result = enrollmentStorage.Forget();
            if (result is not (EnrollmentStorageResult.Forgotten or EnrollmentStorageResult.NotFound))
            {
                throw StorageFailure("The protected endpoint enrollment metadata could not be forgotten. Retry the identity reset.");
            }
        }
    }

    /// <summary>
    /// Loads the protected deployment transport trust and enrollment receipt
    /// needed for endpoint polling. Version-1 through version-3 receipts remain
    /// stored but require local re-enrollment before protected operations.
    /// </summary>
    public static EndpointEnrollmentConfiguration? ReadSavedConfiguration()
    {
        using var storage = new EnrollmentStorage(GetStorageDirectory());
        if (!storage.Exists())
        {
            return null;
        }

        var result = storage.Open(out var bytes);
        try
        {
            if (result != EnrollmentStorageResult.Success || bytes is null)
            {
                throw StorageFailure("Saved endpoint enrollment state could not be read. It was not replaced.");
            }

            var stored = JsonSerializer.Deserialize<StoredEndpointEnrollment>(bytes, JsonOptions);
            if (stored is null || stored.Version is 1 or 2 or 3)
            {
                return null;
            }
            if (stored.Version != 4 || !IsValidDeploymentId(stored.DeploymentId) ||
                stored.Computer is null || !IsValidStoredResult(stored.Computer) ||
                string.IsNullOrWhiteSpace(stored.Origin) ||
                string.IsNullOrWhiteSpace(stored.CaCertificateDerBase64) ||
                string.IsNullOrWhiteSpace(stored.CaFingerprintSha256Hex) ||
                !IsCanonicalLowerHex(stored.GrantVerificationPublicKeyHex, 32) ||
                !stored.AuthorityGeneration.HasValue || stored.AuthorityGeneration.Value <= 0)
            {
                throw StorageFailure("Saved endpoint transport trust is invalid. It was not replaced.");
            }

            var caDer = Convert.FromBase64String(stored.CaCertificateDerBase64);
            try
            {
                var origin = new Uri(stored.Origin, UriKind.Absolute);
                var trust = DeploymentTlsTrust.Create(
                    stored.DeploymentId,
                    origin,
                    caDer,
                    stored.CaFingerprintSha256Hex);
                return new EndpointEnrollmentConfiguration(
                    stored.Computer,
                    trust,
                    stored.GrantVerificationPublicKeyHex,
                    stored.AuthorityGeneration);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(caDer);
            }
        }
        catch (JsonException exception)
        {
            throw StorageFailure("Saved endpoint enrollment state is invalid. It was not replaced.", exception);
        }
        catch (UriFormatException exception)
        {
            throw StorageFailure("Saved endpoint transport origin is invalid. It was not replaced.", exception);
        }
        catch (FormatException exception)
        {
            throw StorageFailure("Saved endpoint transport trust is invalid. It was not replaced.", exception);
        }
        catch (DeploymentTlsTrustException exception)
        {
            throw StorageFailure("Saved endpoint transport trust is invalid. It was not replaced.", exception);
        }
        finally
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    internal static string GetStorageDirectory()
    {
        var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localData))
        {
            throw StorageFailure("Windows did not provide a protected per-user data directory.");
        }

        return Path.Combine(localData, "Helicoid", "Computer", "EndpointIdentity");
    }

    public void Dispose() => _transport.Dispose();

    private sealed record EndpointEnrollmentRequest(
        [property: JsonPropertyName("invitation_id")] string InvitationId,
        [property: JsonPropertyName("enrollment_code")] string EnrollmentCode,
        [property: JsonPropertyName("public_key")] string PublicKey,
        [property: JsonPropertyName("proof")] string Proof);

    private sealed record StoredEndpointEnrollment(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("deployment_id")] string DeploymentId,
        [property: JsonPropertyName("computer")] EndpointEnrollmentResult Computer,
        [property: JsonPropertyName("origin")] string? Origin,
        [property: JsonPropertyName("ca_certificate_der_base64")] string? CaCertificateDerBase64,
        [property: JsonPropertyName("ca_fingerprint_sha256_hex")] string? CaFingerprintSha256Hex,
        [property: JsonPropertyName("grant_verification_public_key_hex")] string? GrantVerificationPublicKeyHex = null,
        [property: JsonPropertyName("authority_generation")] long? AuthorityGeneration = null);

    private sealed record DeploymentAuthorityCheckpoint(
        string GrantVerificationPublicKeyHex,
        long AuthorityGeneration);
}

/// <summary>Protected endpoint enrollment and deployment transport trust.</summary>
public sealed record EndpointEnrollmentConfiguration(
    EndpointEnrollmentResult Enrollment,
    DeploymentTlsTrust Trust,
    string? GrantVerificationPublicKeyHex = null,
    long? AuthorityGeneration = null);

/// <summary>Validated server-side identity returned after invitation redemption.</summary>
public sealed record EndpointEnrollmentResult(
    [property: JsonPropertyName("id")] string ComputerId,
    [property: JsonPropertyName("friendly_name")] string FriendlyName,
    [property: JsonPropertyName("platform")] string Platform,
    [property: JsonPropertyName("enrollment_state")] string EnrollmentState,
    [property: JsonPropertyName("enrollment_epoch")] int EnrollmentEpoch);
