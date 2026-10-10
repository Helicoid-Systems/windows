using System.Text;
using Helicoid.WindowsPlatform.Native;
using Xunit;

namespace Helicoid.Domain.Tests;

public sealed class DesktopNameDecoderTests
{
    [Theory]
    [InlineData("Default\0", true)]
    [InlineData("Winlogon\0", true)]
    [InlineData("Default\0Winlogon\0", false)]
    [InlineData("Default\0\0", false)]
    [InlineData("Default", false)]
    [InlineData("\0", false)]
    public void RequiresOneFinalTerminator(string text, bool expected)
    {
        var bytes = Encoding.Unicode.GetBytes(text);
        Assert.Equal(expected, DesktopNameReader.TryDecodeBoundedUtf16(bytes, bytes.Length, out var name));
        if (expected)
        {
            Assert.Equal(text[..^1], name);
        }
        else
        {
            Assert.Null(name);
        }
    }

    [Fact]
    public void RejectsUnpairedSurrogate()
    {
        byte[] bytes = [0x00, 0xd8, 0x00, 0x00];
        Assert.False(DesktopNameReader.TryDecodeBoundedUtf16(bytes, bytes.Length, out _));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(6)]
    public void RejectsInvalidReportedLength(int written)
    {
        byte[] bytes = [0x41, 0x00, 0x00, 0x00];
        Assert.False(DesktopNameReader.TryDecodeBoundedUtf16(bytes, written, out _));
    }

    [Fact]
    public void RejectsOverlongName()
    {
        var bytes = Encoding.Unicode.GetBytes(new string('A', 129) + "\0");
        Assert.False(DesktopNameReader.TryDecodeBoundedUtf16(bytes, bytes.Length, out _));
    }
}
