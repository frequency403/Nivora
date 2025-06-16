using System.Text;

namespace Nivora.Core.Models;

public record VaultParameters
{
    private const string MagicNumber = "NIVR";
    public byte[]? Salt { get; set; }
    public int Argon2Memory { get; set; } = 65536; // 64 MB
    public int Argon2Iterations { get; set; } = 3;
    public int Argon2Parallelism { get; set; } = 1;
    public byte[] Iv { get; set; } = [];

    public byte[] Content { get; set; } = [];

    public VaultVersion Version { get; private set; } = VaultVersion.Current;


    public static VaultParameters Default => new()
    {
        Salt = Models.Salt.Generate().Bytes,
        Argon2Memory = 65536, // 64 MB
        Argon2Iterations = 3,
        Argon2Parallelism = 1,
        Iv = Aes256.GenerateRandomIv() // Default IV size for AES is 16 bytes
    };

    public async Task<TlvStream> WriteToTlvStream(CancellationToken cancellationToken = default)
    {
        var tlvElements = new List<TlvElement>
        {
            TlvElement.Magic,
            TlvElement.Version,
            TlvElement.SaltFromBytes(Salt ?? Models.Salt.Generate().Bytes),
            TlvElement.Argon2Memory(Argon2Memory),
            TlvElement.Argon2Iterations(Argon2Iterations),
            TlvElement.Argon2Parallelism(Argon2Parallelism),
            TlvElement.Iv(Iv),
            TlvElement.Content(Content)
        };
        var tlvStream = new TlvStream();
        await tlvStream.WriteAllAsync(tlvElements, cancellationToken);
        return tlvStream;
    }

    public static async Task<VaultParameters> ReadFromTlvStream(TlvStream tlvStream,
        CancellationToken cancellationToken = default)
    {
        var parameters = new VaultParameters();
        TlvElement? magicElement = null;
        TlvElement? versionElement = null;
        TlvElement? saltElement = null;
        TlvElement? argon2MemoryElement = null;
        TlvElement? argon2IterationsElement = null;
        TlvElement? argon2ParallelismElement = null;
        TlvElement? ivElement = null;
        TlvElement? contentElement = null;

        await foreach (var element in tlvStream.ReadAllAsync(cancellationToken))
            if (TlvTag.Magic.Equals(element.Tag))
                magicElement = element;
            else if (TlvTag.Version.Equals(element.Tag))
                versionElement = element;
            else if (TlvTag.Salt.Equals(element.Tag))
                saltElement = element;
            else if (TlvTag.Argon2Memory.Equals(element.Tag))
                argon2MemoryElement = element;
            else if (TlvTag.Argon2Iterations.Equals(element.Tag))
                argon2IterationsElement = element;
            else if (TlvTag.Argon2Parallelism.Equals(element.Tag))
                argon2ParallelismElement = element;
            else if (TlvTag.Iv.Equals(element.Tag))
                ivElement = element;
            else if (TlvTag.Content.Equals(element.Tag)) contentElement = element;

        if (magicElement == null || versionElement == null || saltElement == null ||
            argon2MemoryElement == null || argon2IterationsElement == null ||
            argon2ParallelismElement == null || ivElement == null || contentElement == null)
            throw new InvalidOperationException("Invalid vault file format.");

        if (magicElement.Value.Length != 4 || !Encoding.UTF8.GetString(magicElement.Value).Equals(MagicNumber))
            throw new InvalidOperationException("Invalid vault file format.");

        if (!VaultVersion.TryFromBytes(versionElement.Value, out var version))
            throw new InvalidOperationException("Unsupported or unknown vault version.");

        parameters.Version = version;
        parameters.Salt = saltElement.Value;
        parameters.Argon2Memory = BitConverter.ToInt32(argon2MemoryElement.Value, 0);
        parameters.Argon2Iterations = BitConverter.ToInt32(argon2IterationsElement.Value, 0);
        parameters.Argon2Parallelism = BitConverter.ToInt32(argon2ParallelismElement.Value, 0);
        if (parameters.Argon2Memory <= 0 || parameters.Argon2Iterations <= 0 || parameters.Argon2Parallelism <= 0)
            throw new InvalidOperationException("Argon2 parameters must be positive integers.");
        parameters.Iv = ivElement.Value;
        if (parameters.Iv.Length != 16) throw new InvalidOperationException("IV must be exactly 16 bytes long.");
        parameters.Content = contentElement.Value;
        if (parameters.Content.Length == 0) throw new InvalidOperationException("Content cannot be empty.");
        return parameters;
    }
}