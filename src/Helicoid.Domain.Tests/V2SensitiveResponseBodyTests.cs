using System.Text;
using Helicoid.Domain.Client;
using Xunit;

namespace Helicoid.Domain.Tests;

/// <summary>
/// Wire-body cleanup for token-bearing responses. Parsed immutable strings are
/// a separate limitation and are not claimed to be zeroized.
/// </summary>
public sealed class V2SensitiveResponseBodyTests
{
    [Fact]
    public void ParseSensitiveResponse_ZeroesBodyWhenParserThrows()
    {
        byte[] body = Encoding.UTF8.GetBytes("login-token-body");

        Assert.Throws<InvalidOperationException>(() =>
            V2DeviceKeyChallengeClient.ParseSensitiveResponse<int>(
                body,
                _ => throw new InvalidOperationException("invalid login response")));

        Assert.All(body, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void ParseSensitiveResponse_ZeroesBodyAfterSuccessfulParse()
    {
        byte[] body = Encoding.UTF8.GetBytes("login-token-body");

        int length = V2DeviceKeyChallengeClient.ParseSensitiveResponse(
            body,
            value => value.Length);

        Assert.Equal("login-token-body".Length, length);
        Assert.All(body, value => Assert.Equal((byte)0, value));
    }
}
