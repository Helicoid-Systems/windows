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
    private readonly Queue<Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>> _responders = new();

    public List<HttpRequestMessage> Requests { get; } = new();

    public List<string?> AuthorizationHeaders { get; } = new();

    public void Enqueue(Func<HttpRequestMessage, HttpResponseMessage> responder) =>
        _responders.Enqueue((req, _) => Task.FromResult(responder(req)));

    public void Enqueue(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder) =>
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

    /// <summary>Headers arrive immediately; the body stream blocks until cancelled or released.</summary>
    public void EnqueueBlockedBody(HttpStatusCode status, string prefix, TaskCompletionSource release)
    {
        Enqueue(async (_, ct) =>
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new BlockingContent(prefix, release, ct),
            };
            return response;
        });
    }

    protected override async Task<HttpResponseMessage> SendAsync(
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

        return await _responders.Dequeue()(request, cancellationToken).ConfigureAwait(false);
    }

    private sealed class BlockingContent : HttpContent
    {
        private readonly string _prefix;
        private readonly TaskCompletionSource _release;
        private readonly CancellationToken _requestToken;

        public BlockingContent(string prefix, TaskCompletionSource release, CancellationToken requestToken)
        {
            _prefix = prefix;
            _release = release;
            _requestToken = requestToken;
        }

        protected override async Task<Stream> CreateContentReadStreamAsync()
        {
            var stream = new BlockingStream(Encoding.UTF8.GetBytes(_prefix), _release, _requestToken);
            return stream;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            CreateContentReadStreamAsync().ContinueWith(
                t => t.Result.CopyToAsync(stream),
                TaskScheduler.Default).Unwrap();

        protected override bool TryComputeLength(out long length)
        {
            length = -1;
            return false;
        }
    }

    private sealed class BlockingStream : Stream
    {
        private readonly byte[] _prefix;
        private readonly TaskCompletionSource _release;
        private readonly CancellationToken _requestToken;
        private int _position;

        public BlockingStream(byte[] prefix, TaskCompletionSource release, CancellationToken requestToken)
        {
            _prefix = prefix;
            _release = release;
            _requestToken = requestToken;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer.AsMemory(offset, count), _requestToken).AsTask().GetAwaiter().GetResult();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position < _prefix.Length)
            {
                var n = Math.Min(buffer.Length, _prefix.Length - _position);
                _prefix.AsMemory(_position, n).CopyTo(buffer);
                _position += n;
                return n;
            }

            await using var reg = cancellationToken.Register(
                static state => ((TaskCompletionSource)state!).TrySetCanceled(),
                _release);

            try
            {
                await _release.Task.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw;
            }

            return 0; // EOF after release
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
