using System.Runtime.CompilerServices;
using System.Text;
using Nivora.Core.Models;

namespace Nivora.Core;

/// <summary>
///     Provides methods to write and read custom TLV (Tag-Length-Value) structures, similar to ASN.1 encoding.
/// </summary>
public sealed class TlvStream : IDisposable, IAsyncDisposable
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
    /// Writes a TLV element to the stream asynchronously.
    /// </summary>
    /// <param name="element">The TLV element to write.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A `ValueTask` representing the asynchronous operation.</returns>
    private ValueTask WriteAsync(TlvElement element, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(element);
        return Stream.WriteAsync(element.ToTlvBytes(), cancellationToken);
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
    
    public async Task WriteElementsAsync(IEnumerable<TlvElement> elements, CancellationToken cancellationToken = default)
    {
        foreach (var element in elements.OrderBy(e => e.Tag.Value))
        {
            await WriteAsync(element, cancellationToken);
            await Stream.FlushAsync(cancellationToken);
        }
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
    /// Initializes a new TLV element.
    /// </summary>
    /// <param name="tag">The tag (identifier).</param>
    /// <param name="value">The value as byte array.</param>
    /// <exception cref="ArgumentNullException">Thrown if the value is null.</exception>
    public TlvElement(TlvTag tag, byte[] value)
    {
        Tag = tag;
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets the tag (identifier) of the TLV element.
    /// </summary>
    public TlvTag Tag { get; }

    /// <summary>
    /// Gets the value of the TLV element as a byte array.
    /// </summary>
    public byte[] Value { get; }

    /// <summary>
    /// Creates a predefined TLV element representing the magic number.
    /// </summary>
    public static TlvElement Magic => new(TlvTag.Magic, Encoding.UTF8.GetBytes(MagicNumber));

    /// <summary>
    /// Creates a predefined TLV element representing the current version.
    /// </summary>
    public static TlvElement Version => new(TlvTag.Version, VaultVersion.Current.ToBytes());

    /// <summary>
    /// Creates a TLV element representing an initialization vector (IV).
    /// </summary>
    /// <param name="iv">The initialization vector as a byte array.</param>
    /// <returns>A new TLV element.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the IV is null.</exception>
    public static TlvElement Iv(byte[] iv)
    {
        return new TlvElement(TlvTag.Iv, iv ?? throw new ArgumentNullException(nameof(iv)));
    }

    /// <summary>
    /// Creates a TLV element representing content.
    /// </summary>
    /// <param name="content">The content as a byte array.</param>
    /// <returns>A new TLV element.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the content is null.</exception>
    public static TlvElement Content(byte[] content)
    {
        return new TlvElement(TlvTag.Content, content ?? throw new ArgumentNullException(nameof(content)));
    }
    
    /// <summary>
    /// Converts the TLV element into a byte array representation.
    /// The format includes the tag, length (big-endian, 4 bytes), and value.
    /// </summary>
    /// <returns>A byte array representing the TLV element.</returns>
    public byte[] ToTlvBytes()
    {
        var lengthBytes = BitConverter.GetBytes(Value.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);
    
        var result = new byte[1 + 4 + Value.Length];
        result[0] = Tag.Value; // Write Tag
        Array.Copy(lengthBytes, 0, result, 1, 4); // Write Length
        Array.Copy(Value, 0, result, 5, Value.Length); // Write Value
    
        return result;
    }
}

/// <summary>
/// Represents a tag in a TLV (Tag-Length-Value) structure.
/// </summary>
public record TlvTag
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TlvTag"/> class with the specified byte value.
    /// </summary>
    /// <param name="Value">The byte value representing the tag.</param>
    private TlvTag(byte Value)
    {
        this.Value = Value;
    }

    /// <summary>
    /// Gets the byte value of the tag.
    /// </summary>
    public byte Value { get; }

    /// <summary>
    /// Predefined tag representing a magic number (0x01).
    /// </summary>
    public static TlvTag Magic => new(0x01);

    /// <summary>
    /// Predefined tag representing a version (0x02).
    /// </summary>
    public static TlvTag Version => new(0x02);

    /// <summary>
    /// Predefined tag representing an initialization vector (0x03).
    /// </summary>
    public static TlvTag Iv => new(0x03);

    /// <summary>
    /// Predefined tag representing content (0x04).
    /// </summary>
    public static TlvTag Content => new(0x04);

    /// <summary>
    /// Converts a byte value into a corresponding <see cref="TlvTag"/> instance.
    /// </summary>
    /// <param name="value">The byte value to convert.</param>
    /// <returns>The corresponding <see cref="TlvTag"/> instance.</returns>
    /// <exception cref="InvalidDataException">Thrown if the byte value does not match any predefined tag.</exception>
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