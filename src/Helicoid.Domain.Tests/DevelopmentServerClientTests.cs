using System.Net;
using System.Text;
using Helicoid.Domain.Client;
using Helicoid.Domain.Model;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Scripted handler for HTTP client tests. Captures requests without logging
/// Authorization values or credentials.
/// </summary>
internal sealed class ScriptedHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responders = new();

    public List<HttpRequestMessage> Requests { get; } = new();

    public List<string?> AuthorizationHeaders { get; } = new();

    public void Enqueue(Func<HttpRequestMessage, HttpResponseMessage> responder) =>
        _responders.Enqueue(responder);

    public void EnqueueJson(HttpStatusCode status, string json, bool withRedirect = false)
    {
        Enqueue(_ =>
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            if (withRedirect)
            {
                response.Headers.Location = new Uri("http://example.invalid/escape");
            }

            return response;
        });
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Record only the presence of an Authorization header, never its value.
        Requests.Add(request);
        AuthorizationHeaders.Add(request.Headers.Authorization is null ? null : "<present>");

        if (_responders.Count == 0)
        {
            throw new InvalidOperationException("No scripted response remains.");
        }

        return Task.FromResult(_responders.Dequeue()(request));
    }
}

public class LoopbackAddressTests
{
    [Theory]
    [InlineData("http://127.0.0.1:8787")]
    [InlineData("http://localhost:8787")]
    [InlineData("http://127.0.0.1")]
    [InlineData("http://[::1]:8787")]
    public void AcceptsLiteralLoopback(string address)
    {
        var uri = LoopbackAddress.RequireLoopbackHttp(address);
        Assert.True(LoopbackAddress.IsLoopbackHost(uri.Host));
    }

    [Theory]
    [InlineData("http://example.com:8787")]
    [InlineData("http://10.0.0.5:8787")]
    [InlineData("https://127.0.0.1:8787")]
    [InlineData("file:///tmp/nope")]
    [InlineData("not a url")]
    [InlineData("")]
    public void RefusesNonLoopbackOrInvalid(string address)
    {
        Assert.Throws<ServerClientException>(() => LoopbackAddress.RequireLoopbackHttp(address));
    }

    [Fact]
    public void RemoteHost_IsNotLoopbackFailure()
    {
        var ex = Assert.Throws<ServerClientException>(() =>
            LoopbackAddress.RequireLoopbackHttp("http://192.0.2.10:8787"));
        Assert.Equal(ServerClientFailure.NotLoopback, ex.Failure);
    }
}

public class DevelopmentLaunchOptionsTests
{
    [Fact]
    public void Default_IsClosedProductionClient()
    {
        var options = DevelopmentLaunchOptions.Parse(Array.Empty<string>());
        Assert.False(options.DevelopmentServerEnabled);
        Assert.IsType<ClosedProductionClient>(options.CreateClient());
    }

    [Fact]
    public void DevelopmentServerSwitch_EnablesLoopbackClient()
    {
        var options = DevelopmentLaunchOptions.Parse(new[]
        {
            "--development-server",
            "--development-manager-identity",
            "dev-manager-lab-1",
        });

        Assert.True(options.DevelopmentServerEnabled);
        Assert.Equal("dev-manager-lab-1", options.DevelopmentManagerIdentity);
        var client = options.CreateClient();
        Assert.IsType<DevelopmentServerClient>(client);
    }

    [Fact]
    public void DevelopmentServer_WithExplicitLoopbackAddress()
    {
        var options = DevelopmentLaunchOptions.Parse(new[]
        {
            "--development-server=http://127.0.0.1:8787",
        });

        using var client = (DevelopmentServerClient)options.CreateClient();
        Assert.Equal(new Uri("http://127.0.0.1:8787/"), client.BaseAddress);
    }

    [Fact]
    public void DevelopmentServer_RefusesRemoteAddress()
    {
        var options = DevelopmentLaunchOptions.Parse(new[]
        {
            "--development-server=http://10.0.0.5:8787",
        });

        Assert.Throws<ServerClientException>(() => options.CreateClient());
    }
}

public class DevelopmentServerClientTests
{
    private static readonly Uri Loopback = new("http://127.0.0.1:8787/");

    private static DevelopmentServerClient Create(ScriptedHttpMessageHandler handler) =>
        new(Loopback, handler);

    [Fact]
    public async Task Health_ParsesContractJson()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "status": "ok",
              "accepting_authorized_operations": true,
              "schema_version": 1,
              "bootstrap_completed": true,
              "features": { "local_accounts": true, "remote_control": false }
            }
            """);

        using var client = Create(handler);
        var health = await client.GetHealthAsync(CancellationToken.None);

        Assert.Equal("ok", health.Status);
        Assert.True(health.AcceptingAuthorizedOperations);
        Assert.Equal(1, health.SchemaVersion);
        Assert.True(health.Features!["local_accounts"]);
        Assert.False(health.Features["remote_control"]);
    }

    [Fact]
    public async Task Login_StoresSessionAndDoesNotLogToken()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": { "id": "acct-1", "username": "admin", "state": "active", "revision": 1 },
              "manager": { "id": "mgr-1", "public_identity": "dev-manager", "lifecycle_state": "approved" },
              "mfa": { "required": false, "available": false, "reason": "mfa_not_implemented_in_this_foundation" }
            }
            """);

        using var client = Create(handler);
        var login = await client.LoginAsync("admin", "at-least-12-characters", "dev-manager", CancellationToken.None);

        Assert.True(client.HasSession);
        Assert.Equal("admin", login.Account!.Username);
        Assert.Equal("approved", login.Manager!.LifecycleState);
        // Second call must send a bearer header; test records presence only.
        handler.EnqueueJson(HttpStatusCode.OK, """
            { "account": { "id": "acct-1", "username": "admin", "state": "active", "revision": 1 }, "manager": null, "expires_at_unix": 1760086400 }
            """);
        _ = await client.GetSessionAsync(CancellationToken.None);
        Assert.Equal("<present>", handler.AuthorizationHeaders[^1]);
    }

    [Fact]
    public async Task Login_InvalidCredentials_IsUnauthorizedNamedFailure()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.Unauthorized, """
            { "error": { "code": "unauthorized", "message": "invalid credentials" } }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "wrong-password", null, CancellationToken.None));

        Assert.Equal(ServerClientFailure.Unauthorized, ex.Failure);
        Assert.Equal("unauthorized", ex.ErrorCode);
        Assert.Equal(401, ex.HttpStatus);
        Assert.False(client.HasSession);
        // Message must not echo the password.
        Assert.DoesNotContain("wrong-password", ex.Message);
    }

    [Fact]
    public async Task Login_ManagerNotApproved_IsForbidden()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.Forbidden, """
            { "error": { "code": "forbidden", "message": "manager is not approved" } }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", "pending-manager", CancellationToken.None));

        Assert.Equal(ServerClientFailure.Forbidden, ex.Failure);
        Assert.Equal(403, ex.HttpStatus);
    }

    [Fact]
    public async Task Login_RateLimited_IsNamedFailure()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.TooManyRequests, """
            { "error": { "code": "rate_limited", "message": "sign-in throttle" } }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));

        Assert.Equal(ServerClientFailure.RateLimited, ex.Failure);
    }

    [Fact]
    public async Task Inventory_MapsEnrollmentStatesToHonestStatus()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": { "id": "a", "username": "admin", "state": "active", "revision": 1 }
            }
            """);
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "computers": [
                { "id": "pc-1", "friendly_name": "Lab A", "platform": "windows", "enrollment_state": "enrolled", "enrollment_epoch": 1 },
                { "id": "pc-2", "friendly_name": "Lab B", "platform": "macos", "enrollment_state": "pending", "enrollment_epoch": 1 },
                { "id": "pc-3", "friendly_name": "Lab C", "platform": "windows", "enrollment_state": "quarantined", "enrollment_epoch": 2 },
                { "id": "pc-4", "friendly_name": "Lab D", "platform": "windows", "enrollment_state": "revoked", "enrollment_epoch": 1 }
              ],
              "scope_is_explicit": true,
              "max_page_size": 100
            }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        var inventory = await client.GetInventoryAsync(CancellationToken.None);

        Assert.Equal(4, inventory.Count);
        Assert.Equal(ComputerStatus.Offline, inventory[0].Status);
        Assert.Equal(ComputerStatus.PendingApproval, inventory[1].Status);
        Assert.Equal(ComputerStatus.NeedsAttention, inventory[2].Status);
        Assert.Equal(ComputerStatus.Unavailable, inventory[3].Status);
    }

    [Fact]
    public async Task Inventory_WithoutSession_IsNotConnected()
    {
        var handler = new ScriptedHttpMessageHandler();
        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetInventoryAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotConnected, ex.Failure);
    }

    [Fact]
    public async Task Redirect_IsRefusedWithoutFollowing()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.Found, """
            { "error": { "code": "bad_request", "message": "moved" } }
            """, withRedirect: true);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));

        Assert.Equal(ServerClientFailure.RedirectRefused, ex.Failure);
    }

    [Fact]
    public async Task Logout_ClearsSessionEvenIfServerRejects()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": { "id": "a", "username": "admin", "state": "active", "revision": 1 }
            }
            """);
        handler.EnqueueJson(HttpStatusCode.InternalServerError, """
            { "error": { "code": "internal", "message": "storage failure" } }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        Assert.True(client.HasSession);

        await Assert.ThrowsAsync<ServerClientException>(() => client.LogoutAsync(CancellationToken.None));
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task Logout_Success_ClearsSession()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": { "id": "a", "username": "admin", "state": "active", "revision": 1 }
            }
            """);
        handler.EnqueueJson(HttpStatusCode.NoContent, "");

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        await client.LogoutAsync(CancellationToken.None);
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task ClearSession_DropsBearer()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": { "id": "a", "username": "admin", "state": "active", "revision": 1 }
            }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        client.ClearSession();

        Assert.False(client.HasSession);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetSessionAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotConnected, ex.Failure);
    }

    [Fact]
    public async Task MalformedJson_IsInvalidResponse()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, "{ not json");

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task OversizedResponse_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        var huge = new string('x', DevelopmentServerClient.MaxResponseBytes + 1024);
        handler.EnqueueJson(HttpStatusCode.OK, $"{{ \"status\": \"{huge}\" }}");

        using var client = Create(handler);
        await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
    }

    [Fact]
    public async Task SecurityStateUnavailable_IsNamedFailure()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.ServiceUnavailable, """
            {
              "error": {
                "code": "security_state_unavailable",
                "message": "required trusted persistence cannot be read or committed reliably; new authority is paused"
              }
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.SecurityStateUnavailable, ex.Failure);
    }

    [Fact]
    public void Client_RefusesNonLoopbackBaseAddress()
    {
        Assert.Throws<ServerClientException>(() =>
            new DevelopmentServerClient(new Uri("http://example.com:8787/")));
    }

    [Fact]
    public async Task NotFound_IsNamedFailure()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.NotFound, """
            { "error": { "code": "not_found", "message": "unknown resource" } }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotFound, ex.Failure);
    }
}
