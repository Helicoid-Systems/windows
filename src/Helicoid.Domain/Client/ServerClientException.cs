using System.Net;

namespace Helicoid.Domain.Client;

/// <summary>
/// Named failures for the development server client. Messages never include
/// passwords, tokens, or Authorization header values.
/// </summary>
public sealed class ServerClientException : Exception
{
    public ServerClientException(ServerClientFailure failure, string message, Exception? inner = null)
        : base(message, inner)
    {
        Failure = failure;
    }

    public ServerClientFailure Failure { get; }

    public string? ErrorCode { get; init; }

    public int? HttpStatus { get; init; }
}

public enum ServerClientFailure
{
    NotConnected = 0,
    InvalidAddress = 1,
    NotLoopback = 2,
    RedirectRefused = 3,
    Timeout = 4,
    Cancelled = 5,
    Unauthorized = 6,
    Forbidden = 7,
    ManagerNotApproved = 8,
    RateLimited = 9,
    SecurityStateUnavailable = 10,
    NotFound = 11,
    Conflict = 12,
    BadRequest = 13,
    NotAvailableInThisBuild = 14,
    ServerError = 15,
    InvalidResponse = 16,
    TransportFailed = 17,
}

/// <summary>
/// Validates and canonicalizes development server addresses. Literal loopback
/// HTTP only; credentials and fragments are refused; localhost is rewritten to
/// 127.0.0.1 before any network resolution.
/// </summary>
public static class LoopbackAddress
{
    public static bool IsLoopbackHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var trimmed = host.Trim().Trim('[', ']');
        return trimmed.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(trimmed, out var address) && IPAddress.IsLoopback(address));
    }

    /// <summary>
    /// Complete address contract for every construction path:
    /// absolute http URI, loopback host, no userinfo, no fragment.
    /// Host is canonicalized to a literal loopback form.
    /// </summary>
    public static Uri RequireDevelopmentBaseAddress(Uri baseAddress)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);

        if (!baseAddress.IsAbsoluteUri)
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Server address must be an absolute URI.");
        }

        if (!string.Equals(baseAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Development server uses HTTP on loopback only.");
        }

        if (!string.IsNullOrEmpty(baseAddress.UserInfo))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Development server address must not embed credentials.");
        }

        if (!string.IsNullOrEmpty(baseAddress.Fragment))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Development server address must not include a fragment.");
        }

        if (!IsLoopbackHost(baseAddress.Host))
        {
            throw new ServerClientException(
                ServerClientFailure.NotLoopback,
                "Development server must be a literal loopback address (127.0.0.1 or localhost).");
        }

        return CanonicalizeLoopback(baseAddress);
    }

    /// <summary>Rewrite localhost to a literal loopback address before resolution.</summary>
    public static Uri CanonicalizeLoopback(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var host = uri.Host.Trim('[', ']');
        if (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address))
        {
            return uri;
        }

        if (!host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            throw new ServerClientException(ServerClientFailure.NotLoopback,
                "Development server must be a literal loopback address.");
        }

        var builder = new UriBuilder(uri)
        {
            Host = "127.0.0.1",
        };
        return builder.Uri;
    }

    public static Uri RequireLoopbackHttp(string? address, int defaultPort = 8787)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Server address is required.");
        }

        if (!Uri.TryCreate(address.Trim(), UriKind.Absolute, out var uri))
        {
            throw new ServerClientException(
                ServerClientFailure.InvalidAddress,
                "Server address is not a valid absolute URI.");
        }

        return RequireDevelopmentBaseAddress(uri);
    }
}
