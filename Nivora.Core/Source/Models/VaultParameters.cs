using System.Text;

namespace Nivora.Core.Models;

public record VaultParameters
{
    private const string MagicNumber = "NIVR";
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
    public byte[] GetContent(byte[] masterPassword)
    {
        // Parameter validation
        ArgumentNullException.ThrowIfNull(masterPassword);

        byte[] encryptedContentCopy;
        lock (_contentLock)
        {
            // Defensive copy to avoid race conditions.
            encryptedContentCopy = (byte[])_content.Clone();
        }

        // Decrypt content
        return DecryptContent(masterPassword, encryptedContentCopy); // TODO PadBlockCorrupted
    }

    /// <summary>
    /// Sets the content and encrypts it immediately using the specified master password.
    /// </summary>
    /// <param name="masterPassword">Password for encryption.</param>
    /// <param name="content">Plain content to be encrypted and stored.</param>
    public void SetContent(byte[] masterPassword, byte[] content)
    {
        // Parameter validation
        ArgumentNullException.ThrowIfNull(masterPassword);
        ArgumentNullException.ThrowIfNull(content);

        // Encrypt the content first
        var encryptedContent = EncryptContent(masterPassword, content);

        // Write the encrypted content atomically
        lock (_contentLock)
        {
            // Overwrite previous content, zero out if sensitive
            ZeroMemory(_content);
            _content = encryptedContent;
        }
    }

    public VaultVersion Version { get; private set; } = VaultVersion.Current;

    private byte[] EncryptContent(byte[] masterPassword, byte[] decryptedContent)
    {
        if (masterPassword == null || masterPassword.Length == 0)
            throw new ArgumentException("Master password cannot be null or empty.", nameof(masterPassword));
        return Aes256.Encrypt(decryptedContent, masterPassword, Iv);
    }

    private byte[] DecryptContent(byte[] masterPassword, byte[] encryptedContent)
    {
        if (masterPassword == null || masterPassword.Length == 0)
            throw new ArgumentException("Master password cannot be null or empty.", nameof(masterPassword));
        return Aes256.Decrypt(encryptedContent, masterPassword, Iv);
    }

    public static VaultParameters Default => new()
    {
        Iv = Aes256.GenerateRandomIv() // Default IV size for AES is 16 bytes
    };

    public async Task<TlvStream> WriteToTlvStream(CancellationToken cancellationToken = default)
    {
        var tlvElements = new List<TlvElement>()
        {
            TlvElement.Magic,
            TlvElement.Version,
            TlvElement.Iv(Iv),
        };
        lock (_contentLock)
        {
            tlvElements.Add(TlvElement.Content(_content));
        }
        var tlvStream = new TlvStream();
        await tlvStream.WriteElementsAsync(tlvElements, cancellationToken);
        return tlvStream;
    }

    public static async Task<VaultParameters> ReadFromTlvStream(TlvStream tlvStream,
        CancellationToken cancellationToken = default)
    {
        var parameters = new VaultParameters();
        TlvElement? magicElement = null;
        TlvElement? versionElement = null;
        TlvElement? ivElement = null;
        TlvElement? contentElement = null;

        await foreach (var element in tlvStream.ReadAllAsync(cancellationToken))
            if (TlvTag.Magic.Equals(element.Tag))
                magicElement = element;
            else if (TlvTag.Version.Equals(element.Tag))
                versionElement = element;
            else if (TlvTag.Iv.Equals(element.Tag))
                ivElement = element;
            else if (TlvTag.Content.Equals(element.Tag)) contentElement = element;

        var elementsNull = new List<string>();
        if (magicElement == null) elementsNull.Add("Magic");
        if (versionElement == null) elementsNull.Add("Version");
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
        parameters.Iv = ivElement!.Value;
        if (parameters.Iv.Length != 16) throw new InvalidOperationException("IV must be exactly 16 bytes long.");
        parameters.IsContentEncrypted = true;
        parameters._content = contentElement!.Value;
        if (parameters._content.Length == 0) throw new InvalidOperationException("Content cannot be empty.");
        return parameters;
    }
}