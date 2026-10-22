using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Captures the primary interactive desktop as bounded, top-down BGRA frames.
/// The caller must hold a redeemed observation admission and revalidate it
/// before and after each capture.
/// </summary>
internal static class WindowsDesktopFrameCapture
{
    private const int SourceCopy = 0x00CC0020;
    private const int Halftone = 4;
    private const uint DibRgbColors = 0;
    private const uint BiRgb = 0;
    private const int MaxSourceDimension = 16_384;

    public static bool TryCapturePrimaryDisplay(
        out byte[] bgra,
        out uint width,
        out uint height,
        out uint stride)
    {
        bgra = Array.Empty<byte>();
        width = 0;
        height = 0;
        stride = 0;

        if (!PhysicalConsoleObserver.Observe().IsEligible)
        {
            return false;
        }

        int sourceWidth = GetSystemMetrics(0);
        int sourceHeight = GetSystemMetrics(1);
        if (sourceWidth is <= 0 or > MaxSourceDimension ||
            sourceHeight is <= 0 or > MaxSourceDimension)
        {
            return false;
        }

        double scale = Math.Min(1.0, Math.Min(1280.0 / sourceWidth, 720.0 / sourceHeight));
        width = (uint)Math.Max(1, (int)Math.Floor(sourceWidth * scale));
        height = (uint)Math.Max(1, (int)Math.Floor(sourceHeight * scale));
        stride = checked(width * 4);
        int byteCount = checked((int)(stride * height));

        IntPtr screenDc = IntPtr.Zero;
        IntPtr memoryDc = IntPtr.Zero;
        IntPtr bitmap = IntPtr.Zero;
        IntPtr previousBitmap = IntPtr.Zero;
        IntPtr pixels = IntPtr.Zero;
        try
        {
            screenDc = GetDC(IntPtr.Zero);
            if (screenDc == IntPtr.Zero)
            {
                return ResetDimensions(out width, out height, out stride);
            }

            memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == IntPtr.Zero)
            {
                return ResetDimensions(out width, out height, out stride);
            }

            var info = new BitmapInfo
            {
                Header = new BitmapInfoHeader
                {
                    Size = (uint)Marshal.SizeOf<BitmapInfoHeader>(),
                    Width = checked((int)width),
                    Height = -checked((int)height),
                    Planes = 1,
                    BitCount = 32,
                    Compression = BiRgb,
                    SizeImage = checked((uint)byteCount),
                },
            };
            bitmap = CreateDIBSection(
                screenDc, ref info, DibRgbColors, out pixels, IntPtr.Zero, 0);
            if (bitmap == IntPtr.Zero || pixels == IntPtr.Zero)
            {
                return ResetDimensions(out width, out height, out stride);
            }

            previousBitmap = SelectObject(memoryDc, bitmap);
            if (previousBitmap == IntPtr.Zero || previousBitmap == new IntPtr(-1))
            {
                return ResetDimensions(out width, out height, out stride);
            }

            _ = SetStretchBltMode(memoryDc, Halftone);
            if (!StretchBlt(
                    memoryDc,
                    0,
                    0,
                    checked((int)width),
                    checked((int)height),
                    screenDc,
                    0,
                    0,
                    sourceWidth,
                    sourceHeight,
                    SourceCopy))
            {
                return ResetDimensions(out width, out height, out stride);
            }

            if (!PhysicalConsoleObserver.Observe().IsEligible)
            {
                return ResetDimensions(out width, out height, out stride);
            }

            var frame = new byte[byteCount];
            try
            {
                Marshal.Copy(pixels, frame, 0, byteCount);
                for (int index = 3; index < frame.Length; index += 4)
                {
                    frame[index] = byte.MaxValue;
                }
                bgra = frame;
                return true;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(frame);
                throw;
            }
        }
        finally
        {
            if (pixels != IntPtr.Zero)
            {
                try
                {
                    var clearedPixels = new byte[byteCount];
                    Marshal.Copy(clearedPixels, 0, pixels, byteCount);
                    CryptographicOperations.ZeroMemory(clearedPixels);
                }
                catch (Exception)
                {
                    // Continue releasing the GDI objects even if the backing
                    // DIB became unavailable during teardown.
                }
            }
            if (memoryDc != IntPtr.Zero && previousBitmap != IntPtr.Zero &&
                previousBitmap != new IntPtr(-1))
            {
                _ = SelectObject(memoryDc, previousBitmap);
            }
            if (bitmap != IntPtr.Zero)
            {
                _ = DeleteObject(bitmap);
            }
            if (memoryDc != IntPtr.Zero)
            {
                _ = DeleteDC(memoryDc);
            }
            if (screenDc != IntPtr.Zero)
            {
                _ = ReleaseDC(IntPtr.Zero, screenDc);
            }
        }
    }

    private static bool ResetDimensions(out uint width, out uint height, out uint stride)
    {
        width = 0;
        height = 0;
        stride = 0;
        return false;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfo
    {
        public BitmapInfoHeader Header;
        public uint Color;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfoHeader
    {
        public uint Size;
        public int Width;
        public int Height;
        public ushort Planes;
        public ushort BitCount;
        public uint Compression;
        public uint SizeImage;
        public int XPelsPerMeter;
        public int YPelsPerMeter;
        public uint ClrUsed;
        public uint ClrImportant;
    }

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetDC(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int ReleaseDC(IntPtr window, IntPtr deviceContext);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateCompatibleDC(IntPtr deviceContext);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteDC(IntPtr deviceContext);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateDIBSection(
        IntPtr deviceContext,
        ref BitmapInfo info,
        uint usage,
        out IntPtr bits,
        IntPtr section,
        uint offset);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr SelectObject(IntPtr deviceContext, IntPtr value);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteObject(IntPtr value);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern int SetStretchBltMode(IntPtr deviceContext, int mode);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool StretchBlt(
        IntPtr destination,
        int destinationX,
        int destinationY,
        int destinationWidth,
        int destinationHeight,
        IntPtr source,
        int sourceX,
        int sourceY,
        int sourceWidth,
        int sourceHeight,
        int operation);
}
