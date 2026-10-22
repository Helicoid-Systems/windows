using System.Security.Cryptography;
using System.Text;
using Helicoid.WindowsPlatform;
using Xunit;

namespace Helicoid.WindowsIntegrationTests;

public sealed class ObservationFrameSlotTests
{
    private const string ValidMappingName =
        "Local\\HelicoidObservationFrame-0123456789ABCDEF0123456789ABCDEF";

    [Fact]
    public void TryParseMappingRequest_AcceptsCanonicalRandomLocalName()
    {
        byte[] request = Encoding.ASCII.GetBytes(ValidMappingName);
        byte[] expectedNonce = Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF");
        try
        {
            Assert.True(ObservationFrameSlot.TryParseMappingRequest(
                request,
                out string? mappingName,
                out byte[]? nonce));
            Assert.Equal(ValidMappingName, mappingName);
            Assert.Equal(expectedNonce, nonce);
            CryptographicOperations.ZeroMemory(nonce!);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request);
            CryptographicOperations.ZeroMemory(expectedNonce);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("Global\\HelicoidObservationFrame-0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("Local\\HelicoidObservationFrame-0123456789abcdef0123456789abcdef")]
    [InlineData("Local\\HelicoidObservationFrame-0123456789ABCDEF")]
    [InlineData("Local\\HelicoidObservationFrame-0123456789ABCDEF0123456789ABCDEZ")]
    public void TryParseMappingRequest_RejectsMalformedOrNonLocalName(string value)
    {
        byte[] request = Encoding.ASCII.GetBytes(value);
        try
        {
            Assert.False(ObservationFrameSlot.TryParseMappingRequest(
                request,
                out string? mappingName,
                out byte[]? nonce));
            Assert.Null(mappingName);
            Assert.Null(nonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request);
        }
    }

    [Fact]
    public void TryParseMappingRequest_RejectsMissingBody()
    {
        Assert.False(ObservationFrameSlot.TryParseMappingRequest(
            null,
            out string? mappingName,
            out byte[]? nonce));
        Assert.Null(mappingName);
        Assert.Null(nonce);
    }
}
