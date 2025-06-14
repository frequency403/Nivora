using System.Text;
using Microsoft.Data.Sqlite;
using Nivora.Core.Database.Models;
using Nivora.Core.Models;

namespace Nivora.Core.Database;

public class Vault : IDisposable, IAsyncDisposable
{
    private const string DefaultVaultExtension = "niv";
    private const string DefaultVaultName = "vault";
    private const string MagicNumber = "NIVR";
    
    public required string Path { get; init; }
    public required VaultVersion Version { get; init; }
    public required SqliteConnection Connection { private get; init; }
    private Vault(){}

    public Secret? GetSecret(string name)
    {
        return null;
    }
    
    public void AddSecret(Secret secret)
    {
        // Implementation for adding a secret to the vault
    }
    
    public void UpdateSecret(Secret secret)
    {
        // Implementation for updating a secret in the vault
    }
    
    public void DeleteSecret(string name)
    {
        // Implementation for deleting a secret from the vault
    }

    private static async Task<Vault?> OpenVault(string path, string password, CancellationToken token)
    {
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
            return null;

        var filePathBytes = GetBytesFromFilePath(fileInfo.FullName);
        var filePathIv = ShuffleBytes(filePathBytes, 16);
        var decryptedFileBytes = Aes256.Decrypt(await File.ReadAllBytesAsync(fileInfo.FullName, token), filePathBytes, filePathIv);
        await using var fileStream = new MemoryStream(decryptedFileBytes);
        await using var tlvStream = new TlvStream(fileStream);
        TlvElement? magicElement = null;
        TlvElement? versionElement = null;
        TlvElement? saltElement = null;
        TlvElement? argon2MemoryElement = null;
        TlvElement? argon2IterationsElement = null;
        TlvElement? argon2ParallelismElement = null;
        TlvElement? ivElement = null;
        TlvElement? contentElement = null;

        await foreach (var element in tlvStream.ReadAllAsync(token))
        {
            if (TlvTag.Magic.Equals(element.Tag))
            {
                magicElement = element;
            }
            else if (TlvTag.Version.Equals(element.Tag))
            {
                versionElement = element;
            }
            else if (TlvTag.Salt.Equals(element.Tag))
            {
                saltElement = element;
            }
            else if (TlvTag.Argon2Memory.Equals(element.Tag))
            {
                argon2MemoryElement = element;
            }
            else if (TlvTag.Argon2Iterations.Equals(element.Tag))
            {
                argon2IterationsElement = element;
            }
            else if (TlvTag.Argon2Parallelism.Equals(element.Tag))
            {
                argon2ParallelismElement = element;
            }
            else if (TlvTag.Iv.Equals(element.Tag))
            {
                ivElement = element;
            }
            else if (TlvTag.Content.Equals(element.Tag))
            {
                contentElement = element;
            }
        }
        
        if (magicElement == null || versionElement == null || saltElement == null ||
            argon2MemoryElement == null || argon2IterationsElement == null ||
            argon2ParallelismElement == null || ivElement == null || contentElement == null)
        {
            throw new InvalidOperationException("Invalid vault file format.");
        }
        
        if (magicElement.Value.Length != 4 || !Encoding.UTF8.GetString(magicElement.Value).Equals(MagicNumber))
        {
            throw new InvalidOperationException("Invalid vault file format.");
        }
        
        if (!VaultVersion.TryFromBytes(versionElement.Value, out var version))
        {
            throw new InvalidOperationException("Unsupported or unknown vault version.");
        }
        
        var salt = saltElement.Value;
        if (salt.Length < 16)
        {
            throw new InvalidOperationException("Salt must be at least 16 bytes long.");
        }
        var argon2Memory = BitConverter.ToInt32(argon2MemoryElement.Value, 0);
        var argon2Iterations = BitConverter.ToInt32(argon2IterationsElement.Value, 0);
        var argon2Parallelism = BitConverter.ToInt32(argon2ParallelismElement.Value, 0);
        if (argon2Memory <= 0 || argon2Iterations <= 0 || argon2Parallelism <= 0)
        {
            throw new InvalidOperationException("Argon2 parameters must be positive integers.");
        }
        var iv = ivElement.Value;
        if (iv.Length != 16)
        {
            throw new InvalidOperationException("IV must be exactly 16 bytes long.");
        }
        var content = contentElement.Value;
        if (content.Length == 0)
        {
            throw new InvalidOperationException("Content cannot be empty.");
        }

        var derivedKey = await Argon2Hash.HashBytes(password, argon2Iterations, argon2Memory, argon2Parallelism, salt);
        var decryptedContent = Aes256.Decrypt(content, derivedKey, iv);
        var memoryDatabase = new SqliteConnection("Data Source=:memory:");
        await memoryDatabase.OpenAsync(token);

        var tempFilePath = System.IO.Path.GetTempFileName();
        await using (var tempFileStream =
                     new FileStream(tempFilePath, FileMode.OpenOrCreate, FileAccess.Write))
        {
            await tempFileStream.WriteAsync(decryptedContent, token);
            await using (var fileDatabase = new SqliteConnection($"Data Source={tempFileStream.Name};"))
            {
                await fileDatabase.OpenAsync(token);
                fileDatabase.BackupDatabase(memoryDatabase);
                await fileDatabase.CloseAsync();
            }
        }
        await memoryDatabase.CloseAsync();
        File.Delete(tempFilePath);
        
        
        return new Vault
        {
            Path = fileInfo.FullName,
            Version = version,
            Connection = memoryDatabase
        };
    }

    private static async Task<Vault?> CreateVault(string path, string password, CancellationToken token)
    {
        var fileInfo = new FileInfo(path);
        if (fileInfo.Exists)
            throw new InvalidOperationException(
                "Vault file already exists. Please choose a different path or delete the existing file.");
        if (!fileInfo.Directory?.Exists ?? true)
        {
            fileInfo.Directory?.Create();
        }
        
        var salt = Salt.Generate(16).Bytes;
        const int argon2Memory = 65536; // 64 MB
        const int argon2Iterations = 3;
        const int argon2Parallelism = 1;
        var iv = Aes256.GenerateRandomIv();

        // Create a temporary in-memory database
        await using var memoryDatabase = new SqliteConnection("Data Source=:memory:");
        await memoryDatabase.OpenAsync(token);

        // Create tables and initial structure
        await using (var command = memoryDatabase.CreateCommand())
        {
            command.CommandText = Secret.CreateTableSql;
            await command.ExecuteNonQueryAsync(token);
        }

        var tempFilePath = System.IO.Path.GetTempFileName();
        // Backup the in-memory database to a file
        await using (var fileDatabase = new SqliteConnection($"Data Source={tempFilePath};"))
        {
            await fileDatabase.OpenAsync(token);
            memoryDatabase.BackupDatabase(fileDatabase);
            await fileDatabase.CloseAsync();
        }
        
        await using var databaseStream =
            new FileStream(tempFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        await using var encryptedStream = new MemoryStream();
        await Aes256.EncryptStream(databaseStream, encryptedStream, await Argon2Hash.HashBytes(password, argon2Iterations, argon2Memory, argon2Parallelism, salt), iv, token: token);

        // Prepare content for encryption
        await using (var contentStream = new MemoryStream())
        {
            await using (var tlvStream = new TlvStream(contentStream, false))
            {
                await tlvStream.WriteAllAsync([
                    TlvElement.Magic,
                    TlvElement.Version,
                    TlvElement.SaltFromBytes(salt),
                    TlvElement.Argon2Memory(argon2Memory),
                    TlvElement.Argon2Iterations(argon2Iterations),
                    TlvElement.Argon2Parallelism(argon2Parallelism),
                    TlvElement.Iv(iv),
                    TlvElement.Content(encryptedStream.ToArray())
                ], token);
            }
            
            var filePathBytes = GetBytesFromFilePath(fileInfo.FullName);
            var filePathIv = ShuffleBytes(filePathBytes, 16);
            contentStream.Position = 0;
            await using var cryptoStream = new MemoryStream();
            await Aes256.EncryptStream(contentStream, cryptoStream, filePathBytes, filePathIv, token: token);
            await using var fileStream =
                new FileStream(fileInfo.FullName, FileMode.Create, FileAccess.Write, FileShare.None);
            await fileStream.WriteAsync(cryptoStream.ToArray(), token);
        }


        return await OpenVault(path, password, token);
    }

    /// <summary>
    /// Shuffles the input bytes in the pattern 0, N-1, 1, N-2, ... up to a maximum of <paramref name="size"/> elements.
    /// If the input is shorter than <paramref name="size"/>, uses only as many as are available.
    /// </summary>
    /// <param name="input">The input byte array to be permuted.</param>
    /// <param name="size">Maximum number of bytes to output.</param>
    /// <returns>Shuffled byte array.</returns>
    private static byte[] ShuffleBytes(ReadOnlySpan<byte> input, int size)
    {
        var result = new byte[Math.Min(size, input.Length)];
        var left = 0;
        var right = input.Length - 1;
        var index = 0;

        while (index < result.Length && left <= right)
        {
            // Add from left
            if (index < result.Length)
            {
                result[index++] = input[left++];
            }
            // Add from right
            if (index < result.Length && left <= right)
            {
                result[index++] = input[right--];
            }
        }
        return result;
    }

    private static byte[] GetBytesFromFilePath(string path, int count = 32)
    {
        var bytes = Encoding.UTF8.GetBytes(path).TakeLast(count).ToArray();
        if (bytes.Length < count)
        {
            var padding = new byte[count - bytes.Length];
            Array.Fill(padding, (byte)0);
            bytes = bytes.Concat(padding).ToArray();
        }
        return bytes;
    }
    
    private static string GetVaultPath(string? vaultName = null)
    {
        if (string.IsNullOrEmpty(vaultName))
            vaultName = DefaultVaultName;
        return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nivora", $"{vaultName}.{DefaultVaultExtension}");
    }
    
    public static Task<Vault?> CreateNew(string password, string? vaultName = null, CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        return CreateVault(GetVaultPath(vaultName), password, token);
    }
    
    public static Task<Vault?> OpenExisting(string password, string? vaultName = null, CancellationToken token = default) => OpenVault(GetVaultPath(vaultName), password, token);

    public void Dispose()
    {
        Connection.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await Connection.DisposeAsync();
    }
}