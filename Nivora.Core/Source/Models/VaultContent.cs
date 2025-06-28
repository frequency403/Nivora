namespace Nivora.Core.Models;

public sealed class VaultContent
{
    public byte[] Iv { get; }

    private VaultContent(PasswordHash masterPassword, byte[] content, byte[] iv, bool encrypt = false)
    {
        Iv = iv;
        if(!encrypt)
        {
            _content = content;
            return;
        }
        lock (_contentLock)
        {
            _content = EncryptContent(masterPassword, content);
        }
        
    }
    
    public static Task<VaultContent> CreateAsync(PasswordHash masterPassword, byte[] content, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        return Task.Run(() => new VaultContent(masterPassword, content, Aes256.GenerateRandomIv(), true), token);
    }
    
    public static Task<VaultContent> LoadAsync(PasswordHash masterPassword, byte[] content, byte[] iv,  CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        return Task.Run(() => new VaultContent(masterPassword, content, iv), token);
    }
    
    // Private content field, always access through lock for thread safety.
    private byte[] _content;

    // Lock object for synchronization.
    private readonly Lock _contentLock = new Lock();

    /// <summary>
    /// Gets the decrypted content using the provided master password.
    /// </summary>
    /// <param name="masterPassword">The password to decrypt the content.</param>
    /// <returns>Decrypted content as byte array.</returns>
    public byte[] GetContent(PasswordHash masterPassword)
    {
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
    public void SetContent(PasswordHash masterPassword, byte[] content)
    {
        // Parameter validation
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
    
    private byte[] EncryptContent(PasswordHash masterPassword, byte[] decryptedContent)
    {
        if (masterPassword.Length == 0)
            throw new ArgumentException("Master password cannot be null or empty.", nameof(masterPassword));
        return Aes256.Encrypt(decryptedContent, masterPassword.Value, Iv);
    }

    private byte[] DecryptContent(PasswordHash masterPassword, byte[] encryptedContent)
    {
        if (masterPassword.Length == 0)
            throw new ArgumentException("Master password cannot be null or empty.", nameof(masterPassword));
        return Aes256.Decrypt(encryptedContent, masterPassword.Value, Iv);
    }
    
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
}