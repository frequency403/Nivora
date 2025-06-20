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

    private bool IsContentEncrypted { get; set; }

    /// <summary>
    /// Securely overwrites the contents of the byte array with zeros.
    /// </summary>
    private static void ZeroMemory(byte[]? buffer)
    {
        if (buffer == null) return;
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = 0;
        }
    }

    // Private content field, always access through lock for thread safety.
    private byte[] _content = [];

    // Lock object for synchronization.
    private readonly Lock _contentLock = new Lock();

    /// <summary>
    /// Gets the decrypted content using the provided master password.
    /// </summary>
    /// <param name="masterPassword">The password to decrypt the content.</param>
    /// <returns>Decrypted content as byte array.</returns>
    public async Task<byte[]> GetContentAsync(byte[] masterPassword)
    {
        // Parameter validation
        ArgumentNullException.ThrowIfNull(masterPassword);

        byte[] encryptedContentCopy;
        lock (_contentLock)
        {
            // Defensive copy to avoid race conditions.
            encryptedContentCopy = (byte[])_content.Clone();
        }

        // Decrypt content (method must be implemented by you)
        return await DecryptContentAsync(masterPassword, encryptedContentCopy);
    }

    /// <summary>
    /// Sets the content and encrypts it immediately using the specified master password.
    /// </summary>
    /// <param name="masterPassword">Password for encryption.</param>
    /// <param name="content">Plain content to be encrypted and stored.</param>
    public async Task SetContentAsync(byte[] masterPassword, byte[] content)
    {
        // Parameter validation
        ArgumentNullException.ThrowIfNull(masterPassword);
        ArgumentNullException.ThrowIfNull(content);

        // Encrypt the content first
        var encryptedContent = await EncryptContentAsync(masterPassword, content);

        // Write the encrypted content atomically
        lock (_contentLock)
        {
            // Overwrite previous content, zero out if sensitive
            ZeroMemory(_content);
            _content = encryptedContent;
        }
    }

    public VaultVersion Version { get; private set; } = VaultVersion.Current;

    private async Task<byte[]> EncryptContentAsync(byte[] masterPassword, byte[] decryptedContent)
    {
        if (masterPassword == null || masterPassword.Length == 0)
            throw new ArgumentException("Master password cannot be null or empty.", nameof(masterPassword));
        if (Salt == null || Salt.Length == 0)
            throw new InvalidOperationException("Salt must be set before encrypting content.");
        var key = await Argon2Hash.HashBytes(masterPassword, this);
        return Aes256.Encrypt(decryptedContent, key, Iv);
    }

    private async Task<byte[]> DecryptContentAsync(byte[] masterPassword, byte[] encryptedContent)
    {
        if (masterPassword == null || masterPassword.Length == 0)
            throw new ArgumentException("Master password cannot be null or empty.", nameof(masterPassword));
        if (Salt == null || Salt.Length == 0)
            throw new InvalidOperationException("Salt must be set before decrypting content.");
        var key = await Argon2Hash.HashBytes(masterPassword, this);
        return Aes256.Decrypt(encryptedContent, key, Iv);
    }

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
            TlvElement.Content(_content)
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

        var elementsNull = new List<string>();
        if (magicElement == null) elementsNull.Add("Magic");
        if (versionElement == null) elementsNull.Add("Version");
        if (saltElement == null) elementsNull.Add("Salt");
        if (argon2MemoryElement == null) elementsNull.Add("Argon2Memory");
        if (argon2IterationsElement == null) elementsNull.Add("Argon2Iterations");
        if (argon2ParallelismElement == null) elementsNull.Add("Argon2Parallelism");
        if (ivElement == null) elementsNull.Add("IV");
        if (contentElement == null) elementsNull.Add("Content");
        if (elementsNull.Count > 0)
            throw new InvalidOperationException(
                $"Invalid vault file format. Missing elements: {string.Join(", ", elementsNull)}");

        if (magicElement!.Value.Length != 4 || !Encoding.UTF8.GetString(magicElement.Value).Equals(MagicNumber))
            throw new InvalidOperationException("Invalid vault file format. Expected signature not found.");

        if (!VaultVersion.TryFromBytes(versionElement!.Value, out var version))
            throw new InvalidOperationException("Unsupported or unknown vault version.");

        parameters.Version = version;
        parameters.Salt = saltElement!.Value;
        parameters.Argon2Memory = BitConverter.ToInt32(argon2MemoryElement!.Value, 0);
        parameters.Argon2Iterations = BitConverter.ToInt32(argon2IterationsElement!.Value, 0);
        parameters.Argon2Parallelism = BitConverter.ToInt32(argon2ParallelismElement!.Value, 0);
        if (parameters.Argon2Memory <= 0 || parameters.Argon2Iterations <= 0 || parameters.Argon2Parallelism <= 0)
            throw new InvalidOperationException("Argon2 parameters must be positive integers.");
        parameters.Iv = ivElement!.Value;
        if (parameters.Iv.Length != 16) throw new InvalidOperationException("IV must be exactly 16 bytes long.");
        parameters.IsContentEncrypted = true;
        parameters._content = contentElement!.Value;
        if (parameters._content.Length == 0) throw new InvalidOperationException("Content cannot be empty.");
        return parameters;
    }
}