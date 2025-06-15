using static System.GC;

namespace Nivora.Core.Streams;

public class TempFileStream : Stream
{
    private FileStream _fileStream = new(System.IO.Path.GetTempFileName(), FileMode.Create);
    public string Path => _fileStream.Name;

    public override void Flush() => _fileStream.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => 
        _fileStream.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => 
        _fileStream.Read(buffer, offset, count);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _fileStream.ReadAsync(buffer, offset, count, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => 
        _fileStream.Seek(offset, origin);

    public override void SetLength(long value) => 
        _fileStream.SetLength(value);

    public override void Write(byte[] buffer, int offset, int count) =>
        _fileStream.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _fileStream.WriteAsync(buffer, offset, count, cancellationToken);


    public override bool CanRead => _fileStream.CanRead;
    public override bool CanSeek => _fileStream.CanSeek;
    public override bool CanWrite => _fileStream.CanWrite;
    public override long Length => _fileStream.Length;

    public override long Position
    {
        get => _fileStream.Position;
        set => _fileStream.Position = value;
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