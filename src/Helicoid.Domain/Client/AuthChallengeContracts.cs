using System.Text;
using System.Text.Json.Serialization;

namespace Helicoid.Domain.Client;

// DTOs mirror modules/server/contracts/http-v2.md plus the frozen native
// extension (mfa_required on the challenge begin response). No other fields.

/// <summary>POST /v2/auth/challenge request body.</summary>
public sealed class AuthChallengeBeginRequest
{
    [JsonPropertyName("username")]
    public required string Username { get; init; }

    [JsonPropertyName("password")]
    public required string Password { get; init; }

    [JsonPropertyName("operation")]
    public required string Operation { get; init; }

    [JsonPropertyName("manager_public_key")]
    public required string ManagerPublicKey { get; init; }
}

/// <summary>POST /v2/auth/challenge 201 body.</summary>
public sealed class AuthChallengeBeginResponse
{
    [JsonPropertyName("challenge_id")]
    public string ChallengeId { get; init; } = string.Empty;

    [JsonPropertyName("challenge_token")]
    public string ChallengeToken { get; init; } = string.Empty;

    [JsonPropertyName("operation")]
    public string Operation { get; init; } = string.Empty;

    [JsonPropertyName("manager_public_key")]
    public string ManagerPublicKey { get; init; } = string.Empty;

    [JsonPropertyName("deployment_id")]
    public string DeploymentId { get; init; } = string.Empty;

    [JsonPropertyName("expires_at_unix")]
    public long ExpiresAtUnix { get; init; }

    /// <summary>
    /// Frozen native extension. An older genuine v2 response that omits this
    /// field deserializes as null and is treated as required MFA.
    /// </summary>
    [JsonPropertyName("mfa_required")]
    public bool? MfaRequired { get; init; }
}

/// <summary>POST /v2/auth/challenge/complete request body.</summary>
public sealed class AuthChallengeCompleteRequest
{
    [JsonPropertyName("challenge_id")]
    public required string ChallengeId { get; init; }

    [JsonPropertyName("challenge_token")]
    public required string ChallengeToken { get; init; }

    [JsonPropertyName("manager_signature")]
    public required string ManagerSignature { get; init; }

    /// <summary>Six-digit TOTP when required; omitted for optional non-enrolled login.</summary>
    [JsonPropertyName("totp_code")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TotpCode { get; init; }
}

/// <summary>Bound on nonempty challenge identifiers and tokens.</summary>
public static class AuthChallengeBounds
{
    /// <summary>Challenge lifetime the server issues (120 seconds).</summary>
    public const int MaxChallengeLifetimeSeconds = 120;

    /// <summary>Maximum accepted session lifetime after completion (2 hours).</summary>
    public const int MaxSessionLifetimeSeconds = 2 * 60 * 60;

    /// <summary>Maximum accepted identifier / token length.</summary>
    public const int MaxIdentifierLength = 256;

    /// <summary>Canonical v2 challenge operation for ordinary sign-in.</summary>
    public const string SessionOperation = "session";
}

/// <summary>
/// Exact domain-separated message signed by the manager device key.
/// Layout is frozen: hs-auth-v2|deployment:…|challenge:…|operation:…|manager:…
/// </summary>
public static class AuthChallengeMessage
{
    public const string DomainPrefix = "hs-auth-v2";

    public static byte[] BuildCanonical(
        string deploymentId,
        string challengeId,
        string operation,
        string managerPublicKeyHex)
    {
        if (!IsBoundedToken(deploymentId))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge deployment identity is missing or unbounded.");
        }

        if (!IsBoundedToken(challengeId))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge identifier is missing or unbounded.");
        }

        if (string.IsNullOrEmpty(operation) || operation.Length > AuthChallengeBounds.MaxIdentifierLength
            || operation.Any(char.IsControl))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge operation is missing or unbounded.");
        }

        if (!Ed25519DeviceKey.TryParsePublicKey(managerPublicKeyHex, out _))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidResponse,
                "Challenge manager public key is not a 32-byte hex value.");
        }

        var canonical =
            $"{DomainPrefix}|deployment:{deploymentId}|challenge:{challengeId}|operation:{operation}|manager:{managerPublicKeyHex}";
        return Encoding.UTF8.GetBytes(canonical);
    }

    public static bool IsBoundedToken(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= AuthChallengeBounds.MaxIdentifierLength
        && !value.Any(char.IsControl);
}
