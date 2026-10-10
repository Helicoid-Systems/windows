using System.Text.Json.Serialization;

namespace Helicoid.Domain.Client;

// DTOs mirror modules/server/contracts/http-v1.md (version 1).
// Do not invent additional fields. Copy is in contracts/http-v1.md.

public sealed class HealthResponse
{
    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("accepting_authorized_operations")]
    public bool AcceptingAuthorizedOperations { get; init; }

    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("bootstrap_completed")]
    public bool BootstrapCompleted { get; init; }

    [JsonPropertyName("features")]
    public Dictionary<string, bool>? Features { get; init; }
}

public sealed class LoginRequest
{
    [JsonPropertyName("username")]
    public required string Username { get; init; }

    [JsonPropertyName("password")]
    public required string Password { get; init; }

    [JsonPropertyName("manager_public_identity")]
    public string? ManagerPublicIdentity { get; init; }
}

public sealed class AccountDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; init; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; init; } = string.Empty;

    [JsonPropertyName("capabilities")]
    public Dictionary<string, bool>? Capabilities { get; init; }

    [JsonPropertyName("revision")]
    public long Revision { get; init; }
}

public sealed class ManagerDto
{
    [JsonPropertyName("id")]
    public string? Id { get; init; }

    [JsonPropertyName("public_identity")]
    public string? PublicIdentity { get; init; }

    [JsonPropertyName("friendly_name")]
    public string? FriendlyName { get; init; }

    [JsonPropertyName("lifecycle_state")]
    public string? LifecycleState { get; init; }

    [JsonPropertyName("approved_at_unix")]
    public long? ApprovedAtUnix { get; init; }
}

public sealed class MfaDto
{
    [JsonPropertyName("required")]
    public bool Required { get; init; }

    [JsonPropertyName("available")]
    public bool Available { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }
}

public sealed class LoginResponse
{
    [JsonPropertyName("token")]
    public string Token { get; init; } = string.Empty;

    [JsonPropertyName("expires_at_unix")]
    public long ExpiresAtUnix { get; init; }

    [JsonPropertyName("account")]
    public AccountDto? Account { get; init; }

    [JsonPropertyName("manager")]
    public ManagerDto? Manager { get; init; }

    [JsonPropertyName("mfa")]
    public MfaDto? Mfa { get; init; }
}

public sealed class SessionResponse
{
    [JsonPropertyName("account")]
    public AccountDto? Account { get; init; }

    [JsonPropertyName("manager")]
    public ManagerDto? Manager { get; init; }

    [JsonPropertyName("expires_at_unix")]
    public long ExpiresAtUnix { get; init; }
}

public sealed class ComputerDto
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("public_identity")]
    public string? PublicIdentity { get; init; }

    [JsonPropertyName("friendly_name")]
    public string FriendlyName { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    public string Platform { get; init; } = string.Empty;

    [JsonPropertyName("enrollment_state")]
    public string EnrollmentState { get; init; } = string.Empty;

    [JsonPropertyName("enrollment_epoch")]
    public long EnrollmentEpoch { get; init; }
}

public sealed class ComputersResponse
{
    [JsonPropertyName("computers")]
    public List<ComputerDto>? Computers { get; init; }

    [JsonPropertyName("scope_is_explicit")]
    public bool ScopeIsExplicit { get; init; }

    [JsonPropertyName("max_page_size")]
    public int MaxPageSize { get; init; }
}

/// <summary>Non-2xx body from the common error envelope.</summary>
public sealed class ErrorBody
{
    [JsonPropertyName("error")]
    public ErrorDetail? Error { get; init; }
}

public sealed class ErrorDetail
{
    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    [JsonPropertyName("detail")]
    public string? Detail { get; init; }
}
