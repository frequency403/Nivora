using System.Text;
using Dapper;
using Microsoft.Data.Sqlite;
using Nivora.Core.Database.Models;
using Nivora.Core.Exceptions;
using Nivora.Core.Models;
using Nivora.Core.Streams;

namespace Nivora.Core.Database;

public class Vault : IDisposable, IAsyncDisposable
{
    private const string DefaultVaultExtension = "niv";
    private const string DefaultVaultName = "vault";
    private const string MagicNumber = "NIVR";

    public required string Path { get; init; }
    public required VaultVersion Version { get; init; }
    public required SqliteConnection Connection { private get; init; }

    private Vault()
    {
    }

    public async Task<Secret?> GetSecret(string name) =>
        await Connection.QuerySingleOrDefaultAsync<Secret>("SELECT * FROM Secrets WHERE Name = @Name",
            new { Name = name });

    public async Task<Secret?> AddSecret(Secret secret)
    {
        var rowsAffected =
            await Connection.ExecuteAsync("INSERT INTO Secrets (Name, Iv, Value) VALUES (@Name, @Iv, @Value)", secret) >
            0;
        if (rowsAffected) return await GetSecret(secret.Name);
        return null;
    }

    public async Task<Secret?> UpdateSecret(Secret secret)
    {
        var rowsAffected =
            await Connection.ExecuteAsync(
                "UPDATE Secrets SET Iv = @Iv, Value = @Value, UpdatedAt = CURRENT_TIMESTAMP WHERE Name = @Name",
                secret) > 0;
        if (rowsAffected) return await GetSecret(secret.Name);
        return null;
    }

    public async Task<bool> DeleteSecret(string name)
    {
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Name cannot be null or empty.", nameof(name));
        return await Connection.ExecuteAsync("DELETE FROM Secrets WHERE Name = @Name", new { Name = name }) > 0;
    }

    private static async Task<Vault?> OpenVault(string path, string password, CancellationToken token)
    {
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
            return null;

        var filePathBytes = GetBytesFromFilePath(fileInfo.FullName);
        var filePathIv = ShuffleBytes(filePathBytes, 16);
        var decryptedFileBytes = Aes256.Decrypt(await File.ReadAllBytesAsync(fileInfo.FullName, token), filePathBytes,
            filePathIv);
        await using var fileStream = new MemoryStream(decryptedFileBytes);
        await using var tlvStream = new TlvStream(fileStream, true);
        var parameters = await VaultParameters.ReadFromTlvStream(tlvStream, token);

        var derivedKey = await Argon2Hash.HashBytes(password, parameters.Argon2Iterations, parameters.Argon2Memory,
            parameters.Argon2Parallelism, parameters.Salt);
        var decryptedContent = Aes256.Decrypt(parameters.Content, derivedKey, parameters.Iv);
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
            Version = parameters.Version,
            Connection = memoryDatabase
        };
    }

    private static async Task<Vault?> CreateVault(string path, string password, CancellationToken token)
    {
        var fileInfo = new FileInfo(path);
        VaultFileExistsException.ThrowIfExists(fileInfo);
        if (!fileInfo.Directory?.Exists ?? true)
        {
            fileInfo.Directory?.Create();
        }

        var parameters = VaultParameters.Default;

        // Create a temporary in-memory database
        await using var memoryDatabase = new SqliteConnection("Data Source=:memory:");
        await memoryDatabase.OpenAsync(token);

        // Create tables and initial structure
        await using (var command = memoryDatabase.CreateCommand())
        {
            command.CommandText = Secret.CreateTableSql;
            await command.ExecuteNonQueryAsync(token);
        }

        await using var databaseStream = await WriteDatabaseToFile(memoryDatabase, token);
        await using var encryptedStream = new MemoryStream();
        await Aes256.EncryptStream(databaseStream, encryptedStream,
            await Argon2Hash.HashBytes(password, parameters.Argon2Iterations, parameters.Argon2Memory,
                parameters.Argon2Parallelism, parameters.Salt), parameters.Iv, token: token);

        parameters.Content = encryptedStream.ToArray();
        // Prepare content for encryption

        var tlvStream2 = (await parameters.WriteToTlvStream(token)).Stream;
        tlvStream2.Position = 0;
        var filePathBytes = GetBytesFromFilePath(fileInfo.FullName);
        var filePathIv = ShuffleBytes(filePathBytes, 16);
        await using var cryptoStream = new MemoryStream();
        await Aes256.EncryptStream(tlvStream2, cryptoStream, filePathBytes, filePathIv, token: token);
        await using var fileStream =
            new FileStream(fileInfo.FullName, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
        await fileStream.WriteAsync(cryptoStream.ToArray(), token);


        return await OpenVault(fileInfo.FullName, password, token);
    }
    
    private static async Task<Stream> WriteDatabaseToFile(SqliteConnection databaseConnection, CancellationToken token = default)
    {
        var tempFileStream = new TempFileStream();
        // Backup the in-memory database to a file
        await using var fileDatabase = new SqliteConnection($"Data Source={tempFileStream.Path};");
        await fileDatabase.OpenAsync(token);
        databaseConnection.BackupDatabase(fileDatabase);
        await fileDatabase.CloseAsync();

        return tempFileStream;
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
        return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nivora",
            $"{vaultName}.{DefaultVaultExtension}");
    }

    public static Task<Vault?> CreateNew(string password, string? vaultName = null, CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        return CreateVault(GetVaultPath(vaultName), password, token);
    }

    public static Task<Vault?> OpenExisting(string password, string? vaultName = null,
        CancellationToken token = default) => OpenVault(GetVaultPath(vaultName), password, token);

    public void Dispose()
    {
        Connection.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await Connection.DisposeAsync();
    }
}