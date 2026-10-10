using System.Net;
using System.Text;
using Helicoid.Domain.Client;
using Helicoid.Domain.Model;
using Helicoid.Domain.Overview;
using Xunit;

namespace Helicoid.Domain.Tests;

public class ActionSnapshotImmutabilityTests
{
    [Fact]
    public void Freeze_CollectionsCannotBeMutatedThroughCast()
    {
        var id = ComputerId.Parse("pc-1");
        var snapshot = ActionSnapshot.Freeze("Message", new[] { (id, "PC-01") });

        Assert.IsNotType<List<ComputerId>>(snapshot.ComputerIds);
        Assert.IsNotType<List<string>>(snapshot.DisplayNames);
        Assert.IsNotType<ComputerId[]>(snapshot.ComputerIds);

        var asList = snapshot.ComputerIds as IList<ComputerId>;
        Assert.NotNull(asList);
        Assert.Throws<NotSupportedException>(() => asList![0] = ComputerId.Parse("pc-evil"));
        Assert.Throws<NotSupportedException>(() => asList!.Add(ComputerId.Parse("pc-evil")));

        var names = snapshot.DisplayNames as IList<string>;
        Assert.NotNull(names);
        Assert.Throws<NotSupportedException>(() => names![0] = "evil");
        Assert.Equal("PC-01", snapshot.DisplayNames[0]);
        Assert.Equal(id, snapshot.ComputerIds[0]);
    }
}

public class AddressContractTests
{
    [Fact]
    public void Constructor_RefusesEmbeddedCredentials()
    {
        var ex = Assert.Throws<ServerClientException>(() =>
            new DevelopmentServerClient(new Uri("http://user:pass@127.0.0.1:8787/")));
        Assert.Equal(ServerClientFailure.InvalidAddress, ex.Failure);
    }

    [Fact]
    public void Constructor_RefusesFragment()
    {
        var ex = Assert.Throws<ServerClientException>(() =>
            new DevelopmentServerClient(new Uri("http://127.0.0.1:8787/#frag")));
        Assert.Equal(ServerClientFailure.InvalidAddress, ex.Failure);
    }

    [Fact]
    public void Factory_RefusesEmbeddedCredentials()
    {
        var ex = Assert.Throws<ServerClientException>(() =>
            DevelopmentServerClient.CreateLoopback("http://user:pass@127.0.0.1:8787"));
        Assert.Equal(ServerClientFailure.InvalidAddress, ex.Failure);
    }

    [Fact]
    public void Factory_RefusesFragment()
    {
        var ex = Assert.Throws<ServerClientException>(() =>
            DevelopmentServerClient.CreateLoopback("http://127.0.0.1:8787/#frag"));
        Assert.Equal(ServerClientFailure.InvalidAddress, ex.Failure);
    }

    [Fact]
    public void Localhost_IsCanonicalizedToLiteralLoopback()
    {
        using var client = DevelopmentServerClient.CreateLoopback("http://localhost:8787");
        Assert.Equal("127.0.0.1", client.BaseAddress.Host);
        Assert.Equal("127.0.0.1", client.BaseAddress.DnsSafeHost);
    }

    [Fact]
    public void Constructor_AlsoCanonicalizesLocalhost()
    {
        using var client = new DevelopmentServerClient(new Uri("http://localhost:8787/"));
        Assert.Equal("127.0.0.1", client.BaseAddress.Host);
    }
}

public class DevelopmentServerClientRegressionTests
{
    private static readonly Uri Loopback = new("http://127.0.0.1:8787/");

    private static DevelopmentServerClient Create(ScriptedHttpMessageHandler handler) =>
        new(Loopback, handler);

    [Fact]
    public async Task FailedSecondLogin_DoesNotRetainFirstIdentity()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "first-opaque-token",
              "expires_at_unix": 1760086400,
              "account": { "id": "a1", "username": "admin", "state": "active", "revision": 1 }
            }
            """);
        handler.EnqueueJson(HttpStatusCode.Unauthorized, """
            { "error": { "code": "unauthorized", "message": "invalid credentials" } }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        Assert.True(client.HasSession);

        await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "wrong-password", null, CancellationToken.None));

        Assert.False(client.HasSession);
        // Subsequent call must not send the first bearer.
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetSessionAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotConnected, ex.Failure);
    }

    [Fact]
    public async Task FailedSecondLogin_OnValidationError_AlsoClearsFirstIdentity()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "first-opaque-token",
              "expires_at_unix": 1760086400,
              "account": { "id": "a1", "username": "admin", "state": "active", "revision": 1 }
            }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        Assert.True(client.HasSession);

        await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", string.Empty, null, CancellationToken.None));

        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task MalformedInventory_EmptyObject_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": { "id": "a", "username": "admin", "state": "active", "revision": 1 }
            }
            """);
        handler.EnqueueJson(HttpStatusCode.OK, "{}");

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetInventoryAsync(CancellationToken.None));

        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Inventory_MissingComputersList_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": { "id": "a", "username": "admin", "state": "active", "revision": 1 }
            }
            """);
        handler.EnqueueJson(HttpStatusCode.OK, """{ "scope_is_explicit": true, "max_page_size": 100 }""");

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetInventoryAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Inventory_ComputerWithoutId_IsRejected()
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
            { "computers": [ { "friendly_name": "Lab", "platform": "windows", "enrollment_state": "enrolled", "enrollment_epoch": 1 } ], "scope_is_explicit": true, "max_page_size": 100 }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetInventoryAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Login_MissingAccount_IsRejectedAndSessionCleared()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 1760086400,
              "account": null
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));

        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task Login_MissingToken_IsRejectedAndSessionCleared()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "expires_at_unix": 1760086400,
              "account": { "id": "a", "username": "admin", "state": "active", "revision": 1 }
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task Health_MissingRequiredFields_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """{ "accepting_authorized_operations": true }""");

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Session_MissingAccount_IsRejected()
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
            { "account": null, "manager": null, "expires_at_unix": 1760086400 }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetSessionAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Cancellation_IsNamedFailure()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.Enqueue(_ => throw new OperationCanceledException());

        using var client = Create(handler);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(cts.Token));
        Assert.Equal(ServerClientFailure.Cancelled, ex.Failure);
    }

    [Fact]
    public async Task ExactSizeResponse_IsAccepted()
    {
        // Health JSON whose body is exactly MaxResponseBytes, using the string status field.
        const string Prefix = """{"status":""";
        const string Suffix =
            ""","accepting_authorized_operations":true,"schema_version":1,"bootstrap_completed":true}""";
        var padLength = DevelopmentServerClient.MaxResponseBytes
            - Encoding.UTF8.GetByteCount(Prefix)
            - Encoding.UTF8.GetByteCount(Suffix)
            - 2; // surrounding quotes around pad
        Assert.True(padLength > 0);
        var body = Prefix + "\"" + new string('p', padLength) + "\"" + Suffix;
        Assert.Equal(DevelopmentServerClient.MaxResponseBytes, Encoding.UTF8.GetByteCount(body));

        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, body);

        using var client = Create(handler);
        var health = await client.GetHealthAsync(CancellationToken.None);
        Assert.Equal(1, health.SchemaVersion);
    }

    [Fact]
    public async Task ResponseOneByteOverLimit_IsRejected()
    {
        const string Prefix = """{"status":""";
        const string Suffix =
            ""","accepting_authorized_operations":true,"schema_version":1,"bootstrap_completed":true}""";
        var padLength = DevelopmentServerClient.MaxResponseBytes
            - Encoding.UTF8.GetByteCount(Prefix)
            - Encoding.UTF8.GetByteCount(Suffix)
            - 2
            + 1;
        var body = Prefix + "\"" + new string('p', padLength) + "\"" + Suffix;

        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, body);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }
}
