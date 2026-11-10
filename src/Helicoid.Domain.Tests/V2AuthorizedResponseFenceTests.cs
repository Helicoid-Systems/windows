using System.Text;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// The authorized response boundary must not leak a token-bearing body when the
/// session fence rejects the response.
/// </summary>
public sealed class V2AuthorizedResponseFenceTests
{
    [Fact]
    public void CompleteAuthorizedResponse_ZeroesBodyWhenFenceThrows()
    {
        byte[] body = Encoding.UTF8.GetBytes("token-shaped-secret");

        var exception = Assert.Throws<ServerClientException>(() =>
            V2DeviceKeyChallengeClient.CompleteAuthorizedResponse(
                body,
                () => throw new ServerClientException(
                    ServerClientFailure.Unauthorized,
                    "The authorized response belongs to an inactive session.")));

        Assert.Equal(ServerClientFailure.Unauthorized, exception.Failure);
        Assert.All(body, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void CompleteAuthorizedResponse_ReturnsBodyWhenFenceSucceeds()
    {
        byte[] body = Encoding.UTF8.GetBytes("token-shaped-body");

        byte[] returned = V2DeviceKeyChallengeClient.CompleteAuthorizedResponse(
            body,
            static () => { });

        Assert.Same(body, returned);
        Assert.Contains((byte)'t', body);
    }
}
