using System.Text.Json;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Accurate mock bodies matching the real development server contract.
/// Do not relax validation to fit incomplete mocks; extend these fixtures.
/// </summary>
internal static class ContractFixtures
{
    /// <summary>Far-future expiry so tests do not race the clock.</summary>
    public static long FutureExpiryUnix() => DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds();

    public static long PastExpiryUnix() => DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds();

    public static string HealthOk() => $$"""
        {
          "status": "ok",
          "accepting_authorized_operations": true,
          "schema_version": 1,
          "bootstrap_completed": true,
          "features": {
            "local_accounts": true,
            "manager_enrollment": true,
            "scoped_inventory": true,
            "mfa": false,
            "file_jobs": false,
            "security_recovery": false,
            "remote_control": false,
            "screen_observation": false
          }
        }
        """;

    public static string HealthDegraded() => $$"""
        {
          "status": "degraded",
          "accepting_authorized_operations": false,
          "schema_version": 1,
          "bootstrap_completed": true,
          "features": {
            "local_accounts": true,
            "manager_enrollment": true,
            "scoped_inventory": true,
            "mfa": false,
            "file_jobs": false,
            "security_recovery": false,
            "remote_control": false,
            "screen_observation": false
          }
        }
        """;

    public static string LoginOk(
        string token = "opaque-session-token-value",
        string? managerIdentity = null,
        string managerState = "approved") =>
        $$"""
        {
          "token": "{{token}}",
          "expires_at_unix": {{FutureExpiryUnix()}},
          "account": {
            "id": "acct-1",
            "username": "admin",
            "state": "active",
            "capabilities": {
              "operate": true,
              "manage_enrollment": true,
              "manage_access": true,
              "manage_accounts": true,
              "manage_security": true
            },
            "revision": 1
          },
          "manager": {{ManagerJson(managerIdentity, managerState)}},
          "mfa": {
            "required": false,
            "available": false,
            "reason": "mfa_not_implemented_in_this_foundation"
          }
        }
        """;

    public static string SessionOk() =>
        $$"""
        {
          "account": {
            "id": "acct-1",
            "username": "admin",
            "state": "active",
            "capabilities": {
              "operate": true,
              "manage_enrollment": true
            },
            "revision": 1
          },
          "manager": null,
          "expires_at_unix": {{FutureExpiryUnix()}}
        }
        """;

    public static string SessionExpired() =>
        $$"""
        {
          "account": {
            "id": "acct-1",
            "username": "admin",
            "state": "active",
            "capabilities": {
              "operate": true
            },
            "revision": 1
          },
          "manager": null,
          "expires_at_unix": {{PastExpiryUnix()}}
        }
        """;

    private static string ManagerJson(string? identity, string state) =>
        identity is null
            ? "null"
            : $$"""
              {
                "id": "mgr-1",
                "public_identity": "{{identity}}",
                "friendly_name": "Dev manager",
                "lifecycle_state": "{{state}}",
                "approved_at_unix": 1760000000
              }
              """;
}
