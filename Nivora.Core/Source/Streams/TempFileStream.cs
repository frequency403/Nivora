namespace Nivora.Core.Streams;

public class TempFileStream : Stream
{
    private FileStream _fileStream = new(System.IO.Path.GetTempFileName(), FileMode.Create);
    public string Path => _fileStream.Name;


    public override bool CanRead => _fileStream.CanRead;
    public override bool CanSeek => _fileStream.CanSeek;
    public override bool CanWrite => _fileStream.CanWrite;
    public override long Length => _fileStream.Length;

    public override long Position
    {
        get => _fileStream.Position;
        set => _fileStream.Position = value;
    }

    public override void Flush()
    {
        _fileStream.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return _fileStream.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return _fileStream.Read(buffer, offset, count);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return _fileStream.ReadAsync(buffer, offset, count, cancellationToken);
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = new CancellationToken())
    {
        return _fileStream.ReadAsync(buffer, cancellationToken);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return _fileStream.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        _fileStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _fileStream.Write(buffer, offset, count);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return _fileStream.WriteAsync(buffer, offset, count, cancellationToken);
    }
    
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = new CancellationToken())
    {
        return _fileStream.WriteAsync(buffer, cancellationToken);
    }
    
    public async Task<byte[]> ToArrayAsync(CancellationToken cancellationToken = default)
    {
        if (_fileStream.Length == 0)
            return [];

        await _fileStream.FlushAsync(cancellationToken);
        _fileStream.Seek(0, SeekOrigin.Begin);
        var buffer = new byte[_fileStream.Length];
        await _fileStream.ReadExactlyAsync(buffer, 0, buffer.Length, cancellationToken);
        return buffer;
    }


    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _fileStream?.Dispose();
            _fileStream = null!;
            File.Delete(_fileStream.Name);
        }

        base.Dispose(disposing);
    }

    public override void Close()
    {
        Dispose(true);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_fileStream != null)
        {
            await _fileStream.DisposeAsync();
            File.Delete(_fileStream.Name);
            _fileStream = null!;
        }
    }
}