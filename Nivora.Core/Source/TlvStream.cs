using System.Runtime.CompilerServices;
using System.Text;
using Nivora.Core.Models;

namespace Nivora.Core;

/// <summary>
///     Provides methods to write and read custom TLV (Tag-Length-Value) structures, similar to ASN.1 encoding.
/// </summary>
public class TlvStream : IDisposable, IAsyncDisposable
{
    private readonly bool _closeStream;

    /// <summary>
    ///     Initializes a new instance for reading or writing TLV data.
    /// </summary>
    /// <param name="stream">The underlying stream.</param>
    /// <param name="closeStream">Closes the underlying stream on disposal</param>
    public TlvStream(Stream? stream = null, bool closeStream = true)
    {
        _closeStream = !closeStream ? stream is null : closeStream;
        Stream = stream ?? new MemoryStream();
        Stream.Position = 0;
    }
    
    /// <summary>
    /// Shuffles the input bytes in the pattern 0, N-1, 1, N-2, ... up to a maximum of <paramref name="size" /> elements.
    /// If the input is shorter than <paramref name="size" />, uses only as many as are available.
    /// </summary>
    /// <param name="input">The input byte array to be permuted.</param>
    /// <param name="size">Maximum number of bytes to output.</param>
    /// <returns>Shuffled byte array.</returns>
    private static byte[] ShuffleBytes(byte[] input, int size)
    {
        var result = new byte[Math.Min(size, input.Length)];
        var left = 0;
        var right = input.Length - 1;
        var index = 0;

        while (index < result.Length && left <= right)
        {
            // Add from left
            if (index < result.Length) result[index++] = input[left++];

            // Add from right
            if (index < result.Length && left <= right) result[index++] = input[right--];
        }

        return result;
    }

    /// <summary>
    /// Gets the last <paramref name="count"/> bytes of the file path (UTF-8 encoded), padded with zeros if needed.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="count">Number of bytes to return.</param>
    /// <returns>Byte array for key derivation.</returns>
    private static byte[] GetBytesFromFilePath(string path, int count = 32)
    {
        var bytes = Encoding.UTF8.GetBytes(path).Reverse().Take(count).Reverse().ToArray();
        if (bytes.Length >= count) return bytes;
        var padding = new byte[count - bytes.Length];
        return bytes.Concat(padding).ToArray();
    }
    
    public static async Task<VaultParameters?> ReadEncryptedStream(FileInfo vaultFile, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var encryptedFileStream = vaultFile.OpenRead();
            var filePathBytes = GetBytesFromFilePath(vaultFile.FullName);
            var shuffledBytes = ShuffleBytes(filePathBytes, 16);
            var decryptedFileStream = new MemoryStream();
            await Aes256.DecryptStream(encryptedFileStream, decryptedFileStream, filePathBytes, shuffledBytes,
                token: cancellationToken);
            await using var tlvStream = new TlvStream(decryptedFileStream, closeStream: true);
            var parameters = await VaultParameters.ReadFromTlvStream(tlvStream, cancellationToken);
            return parameters;
        }
        catch (Exception )
        {
            return null;
        }
    }

    public static async Task WriteParametersAndEncrypt(VaultParameters parameters, FileInfo vaultFile,
        CancellationToken cancellationToken = default)
    {
        var filePathBytes = GetBytesFromFilePath(vaultFile.FullName);
        var shuffledBytes = ShuffleBytes(filePathBytes, 16);
        await using var encryptedFileStream = vaultFile.Open(vaultFile.Exists ? FileMode.Truncate : FileMode.CreateNew);
        await using var tlvStream = await parameters.WriteToTlvStream(cancellationToken);
        tlvStream.Stream.Position = 0; // Ensure we start from the beginning
        await Aes256.EncryptStream(tlvStream.Stream, encryptedFileStream, filePathBytes, shuffledBytes, token: cancellationToken);
    }

    private Stream Stream { get; }

    public async ValueTask DisposeAsync()
    {
        if (_closeStream)
            await Stream.DisposeAsync();
    }


    public void Dispose()
    {
        if (_closeStream)
            Stream.Dispose();
    }

    /// <summary>
    ///     Writes a TLV element to the stream.
    /// </summary>
    /// <param name="tag">The tag identifier (1 byte, 0-255).</param>
    /// <param name="value">The value as byte array.</param>
    private void Write(TlvTag tag, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);

        // Write Tag
        Stream.WriteByte(tag.Value);

        // Write Length (4 bytes, big endian)
        var lengthBytes = BitConverter.GetBytes(value.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        Stream.Write(lengthBytes, 0, 4);

        // Write Value
        Stream.Write(value, 0, value.Length);
    }
    
    /// <summary>
    ///     Reads the next TLV element from the stream asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The TLV element or null if end of stream.</returns>
    private async Task<TlvElement?> ReadAsync(CancellationToken cancellationToken = default)
    {
        var tagByte = Stream.ReadByte();
        if (tagByte == -1)
            return null; // End of stream

        var tag = TlvTag.FromByte((byte)tagByte);

        var lengthBytes = new byte[4];
        var readLen = await Stream.ReadAsync(lengthBytes.AsMemory(0, 4), cancellationToken);
        if (readLen != 4)
            throw new EndOfStreamException("Unexpected end of stream while reading TLV length.");

        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        var length = BitConverter.ToInt32(lengthBytes, 0);
        if (length < 0)
            throw new InvalidDataException("Negative length in TLV.");

        var value = new byte[length];
        var read = 0;
        while (read < length)
        {
            var r = await Stream.ReadAsync(value.AsMemory(read, length - read), cancellationToken);
            if (r == 0)
                throw new EndOfStreamException("Unexpected end of stream while reading TLV value.");
            read += r;
        }

        return new TlvElement(tag, value);
    }

    /// <summary>
    ///     Writes multiple TLV elements to the stream.
    /// </summary>
    /// <param name="elements">The TLV elements to write.</param>
    public void WriteElements(IEnumerable<TlvElement> elements)
    {
        foreach (var element in elements.OrderBy(e => e.Tag.Value)) Write(element.Tag, element.Value);
    }

    /// <summary>
    ///     Asynchronously reads all TLV elements from the stream as an IAsyncEnumerable.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>An async enumerable of TLV elements.</returns>
    public async IAsyncEnumerable<TlvElement> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var element = await ReadAsync(cancellationToken);
            if (element == null)
                yield break;
            yield return element;
        }
    }
}

/// <summary>
///     Represents a single TLV (Tag-Length-Value) element.
/// </summary>
public class TlvElement
{
    private const string MagicNumber = "NIVR";

    /// <summary>
    ///     Initializes a new TLV element.
    /// </summary>
    /// <param name="tag">The tag (identifier).</param>
    /// <param name="value">The value as byte array.</param>
    public TlvElement(TlvTag tag, byte[] value)
    {
        Tag = tag;
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    ///     Gets the tag (identifier).
    /// </summary>
    public TlvTag Tag { get; }

    /// <summary>
    ///     Gets the value as byte array.
    /// </summary>
    public byte[] Value { get; }

    public static TlvElement Magic => new(TlvTag.Magic, Encoding.UTF8.GetBytes(MagicNumber));
    public static TlvElement Version => new(TlvTag.Version, VaultVersion.Current.ToBytes());

    public static TlvElement Iv(byte[] iv)
    {
        return new TlvElement(TlvTag.Iv, iv ?? throw new ArgumentNullException(nameof(iv)));
    }

    public static TlvElement Content(byte[] content)
    {
        return new TlvElement(TlvTag.Content, content ?? throw new ArgumentNullException(nameof(content)));
    }
}

public record TlvTag
{
    private TlvTag(byte Value)
    {
        this.Value = Value;
    }

    public byte Value { get; }

    public static TlvTag Magic => new(0x01);
    public static TlvTag Version => new(0x02);
    public static TlvTag Iv => new(0x07);
    public static TlvTag Content => new(0x08);

    internal static TlvTag FromByte(byte value)
    {
        return value switch
        {
            0x01 => Magic,
            0x02 => Version,
            0x03 => Iv,
            0x04 => Content,
            _ => throw new InvalidDataException($"Unknown TLV tag: {value}")
        };
    }
}