using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;
using System.Text;

namespace Helicoid.WindowsPlatform;

internal sealed class CapturedObservationFrame : IDisposable
{
    private byte[]? _pixels;

    internal CapturedObservationFrame(byte[] pixels, uint width, uint height, uint stride)
    {
        _pixels = pixels;
        Width = width;
        Height = height;
        Stride = stride;
    }

    internal byte[] Pixels => _pixels ?? throw new ObjectDisposedException(nameof(CapturedObservationFrame));
    internal uint Width { get; }
    internal uint Height { get; }
    internal uint Stride { get; }

    public void Dispose()
    {
        byte[]? pixels = Interlocked.Exchange(ref _pixels, null);
        if (pixels is not null)
        {
            CryptographicOperations.ZeroMemory(pixels);
        }
    }
}

/// <summary>
/// Transfers one bounded frame from the authenticated per-user worker through
/// a private, one-request named mapping. The worker receives no server token or
/// network authority; the caller creates a slot only for a current admission.
/// </summary>
internal sealed class ObservationFrameSlot : IDisposable
{
    private const string MappingPrefix = "Local\\HelicoidObservationFrame-";
    private const int NonceLength = 16;
    private const int HeaderSize = 48;
    private const int MaxWidth = 1280;
    private const int MaxHeight = 720;
    private const int MaxFrameBytes = MaxWidth * MaxHeight * 4;
    private const int WidthOffset = 24;
    private const int HeightOffset = 28;
    private const int StrideOffset = 32;
    private const int LengthOffset = 36;
    private const int GenerationOffset = 40;
    private static readonly byte[] HeaderMagic = "HSFRM001"u8.ToArray();
    private static readonly byte[] ClearBlock = new byte[64 * 1024];

    private readonly MemoryMappedFile _mapping;
    private readonly MemoryMappedViewAccessor _view;
    private readonly string _mappingName;
    private readonly byte[] _nonce;
    private bool _disposed;

    private ObservationFrameSlot(
        string mappingName,
        byte[] nonce,
        MemoryMappedFile mapping,
        MemoryMappedViewAccessor view)
    {
        _mappingName = mappingName;
        _nonce = nonce;
        _mapping = mapping;
        _view = view;
    }

    internal static ObservationFrameSlot Create()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Observation frame slots require Windows local mappings.");
        }

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);
        string mappingName = MappingPrefix + Convert.ToHexString(nonce);
        MemoryMappedFile? mapping = null;
        MemoryMappedViewAccessor? view = null;
        try
        {
            mapping = MemoryMappedFile.CreateNew(
                mappingName,
                HeaderSize + MaxFrameBytes,
                MemoryMappedFileAccess.ReadWrite);
            view = mapping.CreateViewAccessor(
                0,
                HeaderSize + MaxFrameBytes,
                MemoryMappedFileAccess.ReadWrite);
            return new ObservationFrameSlot(mappingName, nonce, mapping, view);
        }
        catch
        {
            view?.Dispose();
            mapping?.Dispose();
            CryptographicOperations.ZeroMemory(nonce);
            throw;
        }
    }

    internal byte[] CreateRequestBody() => Encoding.ASCII.GetBytes(_mappingName);

    internal CapturedObservationFrame? ReadFrame(uint expectedGeneration)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] header = new byte[HeaderSize];
        _view.ReadArray(0, header, 0, header.Length);
        try
        {
            if (IsAllZero(header))
            {
                return null;
            }

            if (!header.AsSpan(0, HeaderMagic.Length).SequenceEqual(HeaderMagic) ||
                !CryptographicOperations.FixedTimeEquals(
                    header.AsSpan(HeaderMagic.Length, NonceLength), _nonce) ||
                BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(GenerationOffset, 4)) != expectedGeneration)
            {
                throw new InvalidDataException("The capture worker returned a stale or invalid frame header.");
            }

            uint width = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(WidthOffset, 4));
            uint height = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(HeightOffset, 4));
            uint stride = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(StrideOffset, 4));
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(LengthOffset, 4));
            if (width is 0 or > MaxWidth || height is 0 or > MaxHeight ||
                stride != checked(width * 4) || length != checked(stride * height) ||
                length > MaxFrameBytes)
            {
                throw new InvalidDataException("The capture worker returned an out-of-bounds frame.");
            }

            byte[] pixels = new byte[checked((int)length)];
            try
            {
                int read = _view.ReadArray(HeaderSize, pixels, 0, pixels.Length);
                if (read != pixels.Length)
                {
                    throw new InvalidDataException("The capture worker returned a truncated frame.");
                }
                return new CapturedObservationFrame(pixels, width, height, stride);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(pixels);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
        }
    }

    /// <summary>Called only by CaptureWorker after a fenced capture assignment.</summary>
    internal static bool TryCaptureToRequest(byte[]? requestBody, uint generation)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        if (!TryParseMappingRequest(requestBody, out string? mappingName, out byte[]? nonce))
        {
            return false;
        }

        try
        {
            using MemoryMappedFile mapping = MemoryMappedFile.OpenExisting(
                mappingName!, MemoryMappedFileRights.ReadWrite);
            using MemoryMappedViewAccessor view = mapping.CreateViewAccessor(
                0,
                HeaderSize + MaxFrameBytes,
                MemoryMappedFileAccess.ReadWrite);

            if (!WindowsDesktopFrameCapture.TryCapturePrimaryDisplay(
                    out byte[] pixels,
                    out uint width,
                    out uint height,
                    out uint stride))
            {
                return true;
            }

            byte[] header = new byte[HeaderSize];
            try
            {
                if (width is 0 or > MaxWidth || height is 0 or > MaxHeight ||
                    stride != checked(width * 4) ||
                    pixels.Length != checked((int)(stride * height)) ||
                    pixels.Length > MaxFrameBytes)
                {
                    return false;
                }

                view.WriteArray(HeaderSize, pixels, 0, pixels.Length);
                HeaderMagic.CopyTo(header, 0);
                nonce!.CopyTo(header, HeaderMagic.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(WidthOffset, 4), width);
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(HeightOffset, 4), height);
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(StrideOffset, 4), stride);
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(LengthOffset, 4), (uint)pixels.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(GenerationOffset, 4), generation);
                view.WriteArray(0, header, 0, header.Length);
                view.Flush();
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pixels);
                CryptographicOperations.ZeroMemory(header);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce!);
        }
    }

    internal static bool TryParseMappingRequest(
        byte[]? requestBody,
        out string? mappingName,
        out byte[]? nonce)
    {
        mappingName = null;
        nonce = null;
        if (requestBody is null || requestBody.Length != MappingPrefix.Length + NonceLength * 2 ||
            !requestBody.AsSpan(0, MappingPrefix.Length).SequenceEqual(Encoding.ASCII.GetBytes(MappingPrefix)))
        {
            return false;
        }

        for (int index = MappingPrefix.Length; index < requestBody.Length; index++)
        {
            byte value = requestBody[index];
            if (value is not (>= (byte)'0' and <= (byte)'9' or >= (byte)'A' and <= (byte)'F'))
            {
                return false;
            }
        }

        try
        {
            mappingName = Encoding.ASCII.GetString(requestBody);
            nonce = Convert.FromHexString(mappingName.AsSpan(MappingPrefix.Length));
            return nonce.Length == NonceLength;
        }
        catch (FormatException)
        {
            mappingName = null;
            nonce = null;
            return false;
        }
    }

    private static bool IsAllZero(ReadOnlySpan<byte> bytes)
    {
        foreach (byte value in bytes)
        {
            if (value != 0) return false;
        }
        return true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            for (long offset = 0; offset < HeaderSize + MaxFrameBytes; offset += ClearBlock.Length)
            {
                int length = (int)Math.Min(ClearBlock.Length, HeaderSize + MaxFrameBytes - offset);
                _view.WriteArray(offset, ClearBlock, 0, length);
            }
            _view.Flush();
        }
        finally
        {
            _view.Dispose();
            _mapping.Dispose();
            CryptographicOperations.ZeroMemory(_nonce);
        }
    }
}
