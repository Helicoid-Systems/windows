using Helicoid.Domain.Client;
using System.Net;
using Xunit;

namespace Helicoid.Domain.Tests;

public sealed class LoopbackLiteralRegressionTests
{
    [Theory]
    [InlineData("127.attacker.example")]
    [InlineData("127.0.0.1.attacker.example")]
    [InlineData("127.not-an-address")]
    public void DnsNameWithLoopbackPrefixIsRefused(string host)
    {
        Assert.False(LoopbackAddress.IsLoopbackHost(host));
        var error = Assert.Throws<ServerClientException>(() =>
            DevelopmentServerClient.CreateLoopback($"http://{host}:8787"));
        Assert.Equal(ServerClientFailure.NotLoopback, error.Failure);
    }

    [Fact]
    public void Ipv6LoopbackAddressIsPreserved()
    {
        using var client = DevelopmentServerClient.CreateLoopback("http://[::1]:8787");
        Assert.Equal("[::1]", client.BaseAddress.Host);
    }

    [Theory]
    [InlineData("unexpected")]
    [InlineData("degraded")]
    public async Task InvalidReadyStatusIsRejected(string status)
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK,
            ContractFixtures.HealthOk().Replace("\"status\": \"ok\"", $"\"status\": \"{status}\""));
        using var client = DevelopmentServerClient.CreateLoopback("http://127.0.0.1:8787", handler);
        var error = await Assert.ThrowsAsync<ServerClientException>(() => client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, error.Failure);
    }

    [Fact]
    public async Task OversizedExpiryIsRejectedWithoutFrameworkException()
    {
        var handler = new ScriptedHttpMessageHandler();
        var payload = ContractFixtures.LoginOk();
        using var document = System.Text.Json.JsonDocument.Parse(payload);
        var expiry = document.RootElement.GetProperty("expires_at_unix").GetInt64();
        handler.EnqueueJson(HttpStatusCode.OK, payload.Replace(expiry.ToString(), long.MaxValue.ToString()));
        using var client = DevelopmentServerClient.CreateLoopback("http://127.0.0.1:8787", handler);
        var error = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, error.Failure);
        Assert.False(client.HasSession);
    }

    [Fact]
    public void DuplicateInventoryIdsAreRejected()
    {
        var repeated = new ComputerDto { Id = "computer-1", EnrollmentState = "pending" };
        var payload = new ComputersResponse { Computers = [repeated, repeated] };
        var error = Assert.Throws<ServerClientException>(() => DevelopmentServerClient.MapInventory(payload));
        Assert.Equal(ServerClientFailure.InvalidResponse, error.Failure);
    }

    [Fact]
    public void InventoryBeyondServerLimitIsRejected()
    {
        var payload = new ComputersResponse {
            Computers = Enumerable.Range(0, 101)
                .Select(index => new ComputerDto { Id = $"computer-{index}", EnrollmentState = "pending" }).ToList(),
        };
        var error = Assert.Throws<ServerClientException>(() => DevelopmentServerClient.MapInventory(payload));
        Assert.Equal(ServerClientFailure.InvalidResponse, error.Failure);
    }

    [Fact]
    public async Task RequiredMfaIsNotTreatedAsCompletedLogin()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK,
            ContractFixtures.LoginOk().Replace("\"required\": false", "\"required\": true")
                .Replace("\"available\": false", "\"available\": true"));
        using var client = DevelopmentServerClient.CreateLoopback("http://127.0.0.1:8787", handler);
        var error = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotAvailableInThisBuild, error.Failure);
        Assert.False(client.HasSession);
    }
}
