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

    private static DevelopmentServerClient Create(ScriptedHttpMessageHandler handler, TimeSpan? timeout = null) =>
        new(Loopback, handler, timeout);

    [Fact]
    public async Task FailedSecondLogin_DoesNotRetainFirstIdentity()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.LoginOk(token: "first-opaque-token"));
        handler.EnqueueJson(HttpStatusCode.Unauthorized, """
            { "error": { "code": "unauthorized", "message": "invalid credentials" } }
            """);

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        Assert.True(client.HasSession);

        await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "wrong-password", null, CancellationToken.None));

        Assert.False(client.HasSession);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetSessionAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.NotConnected, ex.Failure);
    }

    [Fact]
    public async Task FailedSecondLogin_OnValidationError_AlsoClearsFirstIdentity()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.LoginOk(token: "first-opaque-token"));

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
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.LoginOk());
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
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.LoginOk());
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
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.LoginOk());
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
              "expires_at_unix": 9999999999,
              "account": null,
              "mfa": { "required": false, "available": false }
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
              "expires_at_unix": 9999999999,
              "account": {
                "id": "a", "username": "admin", "state": "active",
                "capabilities": { "operate": true }, "revision": 1
              },
              "mfa": { "required": false, "available": false }
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task Login_AccountWithoutCapabilities_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 9999999999,
              "account": {
                "id": "a", "username": "admin", "state": "active", "revision": 1
              },
              "mfa": { "required": false, "available": false }
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Login_NonActiveAccount_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": 9999999999,
              "account": {
                "id": "a", "username": "admin", "state": "disabled",
                "capabilities": { "operate": true }, "revision": 1
              },
              "mfa": { "required": false, "available": false }
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Login_ExpiredExpiry_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, $$"""
            {
              "token": "opaque-session-token-value",
              "expires_at_unix": {{ContractFixtures.PastExpiryUnix()}},
              "account": {
                "id": "a", "username": "admin", "state": "active",
                "capabilities": { "operate": true }, "revision": 1
              },
              "mfa": { "required": false, "available": false }
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Session_Expired_ClearsBearer()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.LoginOk());
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.SessionExpired());

        using var client = Create(handler);
        await client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None);
        Assert.True(client.HasSession);

        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetSessionAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.Unauthorized, ex.Failure);
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
    public async Task Health_WrongSchemaVersion_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, """
            {
              "status": "ok",
              "accepting_authorized_operations": true,
              "schema_version": 2,
              "bootstrap_completed": true,
              "features": {
                "local_accounts": true,
                "manager_enrollment": true,
                "scoped_inventory": true
              }
            }
            """);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task Session_MissingAccount_IsRejected()
    {
        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, ContractFixtures.LoginOk());
        handler.EnqueueJson(HttpStatusCode.OK, """
            { "account": null, "manager": null, "expires_at_unix": 9999999999 }
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
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.EnqueueBlockedBody(HttpStatusCode.OK, "{", release);

        using var client = Create(handler);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(cts.Token));
        Assert.Equal(ServerClientFailure.Cancelled, ex.Failure);
    }

    [Fact]
    public async Task HeadersThenBlockedBody_TimesOut()
    {
        var handler = new ScriptedHttpMessageHandler();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.EnqueueBlockedBody(HttpStatusCode.OK, "{", release);

        using var client = Create(handler, timeout: TimeSpan.FromMilliseconds(80));
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.Timeout, ex.Failure);
    }

    [Fact]
    public async Task ErrorBody_Cancellation_IsNamedFailure()
    {
        var handler = new ScriptedHttpMessageHandler();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.EnqueueBlockedBody(HttpStatusCode.Unauthorized, """{ "error": { "code": "unauth""", release);

        using var client = Create(handler, timeout: TimeSpan.FromMilliseconds(80));
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.LoginAsync("admin", "at-least-12-characters", null, CancellationToken.None));
        Assert.Equal(ServerClientFailure.Timeout, ex.Failure);
        Assert.False(client.HasSession);
    }

    [Fact]
    public async Task ExactSizeResponse_IsAccepted()
    {
        // Valid health JSON plus trailing whitespace to exactly MaxResponseBytes.
        var json = ContractFixtures.HealthOk();
        var padLength = DevelopmentServerClient.MaxResponseBytes - Encoding.UTF8.GetByteCount(json);
        Assert.True(padLength > 0);
        var body = json + new string(' ', padLength);
        Assert.Equal(DevelopmentServerClient.MaxResponseBytes, Encoding.UTF8.GetByteCount(body));

        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, body);

        using var client = Create(handler);
        var health = await client.GetHealthAsync(CancellationToken.None);
        Assert.Equal(1, health.SchemaVersion);
        Assert.True(health.IsReady);
    }

    [Fact]
    public async Task ResponseOneByteOverLimit_IsRejected()
    {
        var json = ContractFixtures.HealthOk();
        var padLength = DevelopmentServerClient.MaxResponseBytes - Encoding.UTF8.GetByteCount(json) + 1;
        var body = json + new string(' ', padLength);

        var handler = new ScriptedHttpMessageHandler();
        handler.EnqueueJson(HttpStatusCode.OK, body);

        using var client = Create(handler);
        var ex = await Assert.ThrowsAsync<ServerClientException>(() =>
            client.GetHealthAsync(CancellationToken.None));
        Assert.Equal(ServerClientFailure.InvalidResponse, ex.Failure);
    }

    [Fact]
    public async Task ExactLimit_WithDelayedEof_IsAccepted()
    {
        // Full exact-limit body, then the stream blocks before reporting EOF.
        var json = ContractFixtures.HealthOk();
        var padLength = DevelopmentServerClient.MaxResponseBytes - Encoding.UTF8.GetByteCount(json);
        var full = json + new string(' ', padLength);
        Assert.Equal(DevelopmentServerClient.MaxResponseBytes, Encoding.UTF8.GetByteCount(full));

        var handler = new ScriptedHttpMessageHandler();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.Enqueue(async (_, ct) =>
        {
            var content = new DelayedEofContent(full, release, ct);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });

        using var client = Create(handler, timeout: TimeSpan.FromSeconds(5));
        _ = Task.Run(async () =>
        {
            await Task.Delay(30);
            release.TrySetResult();
        });

        var health = await client.GetHealthAsync(CancellationToken.None);
        Assert.True(health.IsReady);
    }

    private sealed class DelayedEofContent : HttpContent
    {
        private readonly string _body;
        private readonly TaskCompletionSource _release;
        private readonly CancellationToken _token;

        public DelayedEofContent(string body, TaskCompletionSource release, CancellationToken token)
        {
            _body = body;
            _release = release;
            _token = token;
        }

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult<Stream>(new DelayedEofStream(Encoding.UTF8.GetBytes(_body), _release, _token));

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            CreateContentReadStreamAsync().ContinueWith(
                t => t.Result.CopyToAsync(stream), TaskScheduler.Default).Unwrap();

        protected override bool TryComputeLength(out long length)
        {
            length = Encoding.UTF8.GetByteCount(_body);
            return true;
        }
    }

    private sealed class DelayedEofStream : Stream
    {
        private readonly byte[] _body;
        private readonly TaskCompletionSource _release;
        private readonly CancellationToken _token;
        private int _position;

        public DelayedEofStream(byte[] body, TaskCompletionSource release, CancellationToken token)
        {
            _body = body;
            _release = release;
            _token = token;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _body.Length;
        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count), _token).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position < _body.Length)
            {
                var n = Math.Min(buffer.Length, _body.Length - _position);
                _body.AsMemory(_position, n).CopyTo(buffer);
                _position += n;
                return n;
            }

            // Delayed EOF: wait for release before reporting end of stream.
            await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
