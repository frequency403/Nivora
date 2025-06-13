using System.Dynamic;

namespace Nivora.Core;

/// <summary>
/// Provides methods to write and read custom TLV (Tag-Length-Value) structures, similar to ASN.1 encoding.
/// </summary>
public class TlvStream : IDisposable, IAsyncDisposable
{
    private readonly Stream _stream;

    /// <summary>
    /// Initializes a new instance for reading or writing TLV data.
    /// </summary>
    /// <param name="stream">The underlying stream.</param>
    public TlvStream(Stream stream)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    /// <summary>
    /// Writes a TLV element to the stream.
    /// </summary>
    /// <param name="tag">The tag identifier (1 byte, 0-255).</param>
    /// <param name="value">The value as byte array.</param>
    public void Write(TlvTag tag, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);

        // Write Tag
        _stream.WriteByte(tag.Value);

        // Write Length (4 bytes, big endian)
        var lengthBytes = BitConverter.GetBytes(value.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        _stream.Write(lengthBytes, 0, 4);

        // Write Value
        _stream.Write(value, 0, value.Length);
    }

    /// <summary>
    /// Writes a TLV element to the stream asynchronously.
    /// </summary>
    /// <param name="tag">The tag identifier.</param>
    /// <param name="value">The value as byte array.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async Task WriteAsync(TlvTag tag, byte[] value, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(value);

        // Write Tag
        _stream.WriteByte(tag.Value);

        // Write Length (4 bytes, big endian)
        var lengthBytes = BitConverter.GetBytes(value.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        await _stream.WriteAsync(lengthBytes, 0, 4, cancellationToken).ConfigureAwait(false);

        // Write Value
        await _stream.WriteAsync(value, 0, value.Length, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the next TLV element from the stream.
    /// </summary>
    /// <returns>The TLV element or null if end of stream.</returns>
    public TlvElement? Read()
    {
        var tagByte = _stream.ReadByte();
        if (tagByte == -1) return null; // End of stream
        var tag = TlvTag.FromByte((byte)tagByte);

        var lengthBytes = new byte[4];
        if (_stream.Read(lengthBytes, 0, 4) != 4)
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
            var r = _stream.Read(value, read, length - read);
            if (r == 0)
                throw new EndOfStreamException("Unexpected end of stream while reading TLV value.");
            read += r;
        }

        return new TlvElement(tag, value);
    }

    /// <summary>
    /// Reads the next TLV element from the stream asynchronously.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The TLV element or null if end of stream.</returns>
    public async Task<TlvElement?> ReadAsync(CancellationToken cancellationToken = default)
    {
        var tagByte = _stream.ReadByte();
        if (tagByte == -1)
            return null; // End of stream

        var tag = TlvTag.FromByte((byte)tagByte);

        var lengthBytes = new byte[4];
        var readLen = await _stream.ReadAsync(lengthBytes, 0, 4, cancellationToken).ConfigureAwait(false);
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
            var r = await _stream.ReadAsync(value, read, length - read, cancellationToken).ConfigureAwait(false);
            if (r == 0)
                throw new EndOfStreamException("Unexpected end of stream while reading TLV value.");
            read += r;
        }

        return new TlvElement(tag, value);
    }

    /// <summary>
    /// Writes multiple TLV elements to the stream.
    /// </summary>
    /// <param name="elements">The TLV elements to write.</param>
    public void WriteElements(IEnumerable<TlvElement> elements)
    {
        foreach (var element in elements)
        {
            Write(element.Tag, element.Value);
        }
    }

    /// <summary>
    /// Writes multiple TLV elements to the stream asynchronously.
    /// </summary>
    /// <param name="elements">The TLV elements to write.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async Task WriteAllAsync(IEnumerable<TlvElement> elements, CancellationToken cancellationToken = default)
    {
        foreach (var element in elements)
        {
            await WriteAsync(element.Tag, element.Value, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reads all TLV elements from the stream until end.
    /// </summary>
    /// <returns>List of TLV elements.</returns>
    public List<TlvElement> ReadAll()
    {
        var list = new List<TlvElement>();
        TlvElement? element;
        while ((element = Read()) != null)
        {
            list.Add(element);
        }
        return list;
    }

    /// <summary>
    /// Asynchronously reads all TLV elements from the stream as an IAsyncEnumerable.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>An async enumerable of TLV elements.</returns>
    public async IAsyncEnumerable<TlvElement> ReadAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var element = await ReadAsync(cancellationToken).ConfigureAwait(false);
            if (element == null)
                yield break;
            yield return element;
        }
    }


    public void Dispose()
    {
        _stream.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync();
    }
}

/// <summary>
/// Represents a single TLV (Tag-Length-Value) element.
/// </summary>
public class TlvElement
{
    /// <summary>
    /// Gets the tag (identifier).
    /// </summary>
    public TlvTag Tag { get; }

    /// <summary>
    /// Gets the value as byte array.
    /// </summary>
    public byte[] Value { get; }

    /// <summary>
    /// Initializes a new TLV element.
    /// </summary>
    /// <param name="tag">The tag (identifier).</param>
    /// <param name="value">The value as byte array.</param>
    public TlvElement(TlvTag tag, byte[] value)
    {
        Tag = tag;
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }
}

public record TlvTag
{
    public byte Value { get; }
    private TlvTag(byte Value)
    {
        this.Value = Value;
    }
    
    internal static TlvTag FromByte(byte value)
    {
        return value switch
        {
            0x01 => Magic,
            0x02 => Version,
            0x03 => Salt,
            0x04 => Argon2Memory,
            0x05 => Argon2Iterations,
            0x06 => Argon2Parallelism,
            0x07 => Iv,
            0x08 => Content,
            _ => throw new InvalidDataException($"Unknown TLV tag: {value}")
        };
    }
    
    public static TlvTag Magic => new(0x01);
    public static TlvTag Version => new(0x02);
    public static TlvTag Salt => new(0x03);
    public static TlvTag Argon2Memory => new(0x04);
    public static TlvTag Argon2Iterations => new(0x05);
    public static TlvTag Argon2Parallelism => new(0x06);
    public static TlvTag Iv => new(0x07);
    public static TlvTag Content => new(0x08);
}