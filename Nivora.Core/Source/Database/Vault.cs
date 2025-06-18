using System.Net;
using Dapper;
using System.Text;
using Microsoft.Data.Sqlite;
using Nivora.Core.Database.Models;
using Nivora.Core.Exceptions;
using Nivora.Core.Models;
using Nivora.Core.Streams;

[module:DapperAot]

namespace Nivora.Core.Database
{
    /// <summary>
    /// Represents a secure vault for storing secrets in an encrypted SQLite database.
    /// </summary>
    public class Vault : IDisposable, IAsyncDisposable
    {
        private const string DefaultVaultExtension = "niv";
        private const string DefaultVaultName = "vault";
        private SqliteConnection _connection;

        // Hide default constructor for controlled initialization
        private Vault() { }

        public string Name => System.IO.Path.GetFileNameWithoutExtension(Path);
        
        /// <summary>
        /// The file path of the vault.
        /// </summary>
        public string Path { get; private set; }

        /// <summary>
        /// The version of the vault.
        /// </summary>
        public VaultVersion Version { get; private set; }

        /// <summary>
        /// The SQLite connection to the vault database.
        /// </summary>
        public SqliteConnection Connection
        {
            get => _connection;
            private set => _connection = value;
        }

        /// <summary>
        /// Asynchronously disposes the vault and its database connection.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            await _connection.DisposeAsync().ConfigureAwait(false);
        }

        /// <summary>
        /// Disposes the vault and its database connection.
        /// </summary>
        public void Dispose()
        {
            _connection.Dispose();
        }

        /// <summary>
        /// Retrieves a secret by name.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <returns>The secret if found, otherwise null.</returns>
        public async Task<Secret?> GetSecret(string name)
        {
            return await _connection.QuerySingleOrDefaultAsync<Secret>(
                "SELECT * FROM Secrets WHERE Name = @Name",
                new { Name = name }).ConfigureAwait(false);
        }

        /// <summary>
        /// Adds a new secret to the vault.
        /// </summary>
        /// <param name="secret">The secret to add.</param>
        /// <returns>The added secret if successful, otherwise null.</returns>
        public async Task<Secret?> AddSecret(Secret secret)
        {
            var rowsAffected = await _connection.ExecuteAsync(
                "INSERT INTO Secrets (Name, Iv, Value) VALUES (@Name, @Iv, @Value)",
                secret).ConfigureAwait(false) > 0;
            if (rowsAffected)
                return await GetSecret(secret.Name).ConfigureAwait(false);
            return null;
        }

        /// <summary>
        /// Updates an existing secret in the vault.
        /// </summary>
        /// <param name="secret">The secret to update.</param>
        /// <returns>The updated secret if successful, otherwise null.</returns>
        public async Task<Secret?> UpdateSecret(Secret secret)
        {
            var rowsAffected = await _connection.ExecuteAsync(
                "UPDATE Secrets SET Iv = @Iv, Value = @Value, UpdatedAt = CURRENT_TIMESTAMP WHERE Name = @Name",
                secret).ConfigureAwait(false) > 0;
            if (rowsAffected)
                return await GetSecret(secret.Name).ConfigureAwait(false);
            return null;
        }

        /// <summary>
        /// Deletes a secret by name.
        /// </summary>
        /// <param name="name">The name of the secret to delete.</param>
        /// <returns>True if the secret was deleted, otherwise false.</returns>
        public async Task<bool> DeleteSecret(string name)
        {
            if (string.IsNullOrEmpty(name))
                throw new ArgumentException("Name cannot be null or empty.", nameof(name));
            return await _connection.ExecuteAsync(
                "DELETE FROM Secrets WHERE Name = @Name",
                new { Name = name }).ConfigureAwait(false) > 0;
        }

        /// <summary>
        /// Opens an existing vault from disk, decrypts it, and loads it into memory.
        /// </summary>
        /// <param name="path">The file path to the vault.</param>
        /// <param name="password">The password to decrypt the vault.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>The opened Vault instance, or null if the file does not exist.</returns>
        private static async Task<Vault> OpenVault(string path, string password, CancellationToken token)
        {
            var fileInfo = new FileInfo(path);
            if (!fileInfo.Exists)
                throw new FileNotFoundException($"Vaultfile '{fileInfo.FullName}' not found.", fileInfo.FullName);

            var filePathBytes = GetBytesFromFilePath(fileInfo.FullName);
            var filePathIv = ShuffleBytes(filePathBytes, 16);

            VaultParameters parameters;
            await using (var encryptedFileStream = new FileStream(
                             fileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            await using (var decryptedFileStream = new MemoryStream())
            await using (var tlvStream = new TlvStream(decryptedFileStream))
            {
                // Decrypt the file
                await Aes256.DecryptStream(
                    encryptedFileStream, decryptedFileStream, filePathBytes, filePathIv, token: token).ConfigureAwait(false);
                decryptedFileStream.Position = 0;
                parameters = await VaultParameters.ReadFromTlvStream(tlvStream, token).ConfigureAwait(false);
            };
             
            var derivedKey = await Argon2Hash.HashBytes(
                password,
                parameters.Argon2Iterations,
                parameters.Argon2Memory,
                parameters.Argon2Parallelism,
                parameters.Salt).ConfigureAwait(false);

            var decryptedContent = Aes256.Decrypt(parameters.Content, derivedKey, parameters.Iv);
            var memoryDatabase = new SqliteConnection("Data Source=:memory:");
            await memoryDatabase.OpenAsync(token).ConfigureAwait(false);

            await using (var tempFileStream = new TempFileStream())
            {
                await tempFileStream.WriteAsync(decryptedContent, token).ConfigureAwait(false);
                await using (var fileDatabase = new SqliteConnection($"Data Source={tempFileStream.Path};"))
                {
                    await fileDatabase.OpenAsync(token).ConfigureAwait(false);
                    fileDatabase.BackupDatabase(memoryDatabase);
                    await fileDatabase.CloseAsync().ConfigureAwait(false);
                }
            }
                    

            return new Vault
            {
                Path = fileInfo.FullName,
                Version = parameters.Version,
                Connection = memoryDatabase
            };
        }

        /// <summary>
        /// Creates a new vault at the specified path with the given password.
        /// </summary>
        /// <param name="path">The file path to create the vault at.</param>
        /// <param name="password">The password for the vault.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>The created Vault instance.</returns>
        private static async Task<Vault> CreateVault(string path, string password, CancellationToken token)
        {
            var fileInfo = new FileInfo(path);
            VaultFileExistsException.ThrowIfExists(fileInfo);
            if (!fileInfo.Directory?.Exists ?? true)
                fileInfo.Directory?.Create();

            var parameters = VaultParameters.Default;

            await using var memoryDatabase = new SqliteConnection("Data Source=:memory:");
            await memoryDatabase.OpenAsync(token).ConfigureAwait(false);

            // Create tables and initial structure
            await using (var command = memoryDatabase.CreateCommand())
            {
                command.CommandText = Secret.CreateTableSql;
                await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            }

            await using (var databaseStream = await WriteDatabaseToFile(memoryDatabase, token).ConfigureAwait(false))
            using (var encryptedStream = new MemoryStream())
            {
                await Aes256.EncryptStream(
                    databaseStream, encryptedStream,
                    await Argon2Hash.HashBytes(
                        password,
                        parameters.Argon2Iterations,
                        parameters.Argon2Memory,
                        parameters.Argon2Parallelism,
                        parameters.Salt).ConfigureAwait(false),
                    parameters.Iv, token: token).ConfigureAwait(false);

                parameters.Content = encryptedStream.ToArray();

                var tlvStream2 = (await parameters.WriteToTlvStream(token).ConfigureAwait(false)).Stream;
                tlvStream2.Position = 0;
                var filePathBytes = GetBytesFromFilePath(fileInfo.FullName);
                var filePathIv = ShuffleBytes(filePathBytes, 16);
                using (var cryptoStream = new MemoryStream())
                {
                    await Aes256.EncryptStream(tlvStream2, cryptoStream, filePathBytes, filePathIv, token: token).ConfigureAwait(false);
                    await using (var fileStream = new FileStream(fileInfo.FullName, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
                    {
                        var buffer = cryptoStream.ToArray();
                        await fileStream.WriteAsync(buffer, token).ConfigureAwait(false);
                    }
                }
            }

            return await OpenVault(fileInfo.FullName, password, token).ConfigureAwait(false);
        }

        /// <summary>
        /// Backups the in-memory database to a temporary file and returns the stream.
        /// </summary>
        /// <param name="databaseConnection">The SQLite connection to backup.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>A TempFileStream containing the backup.</returns>
        private static async Task<TempFileStream> WriteDatabaseToFile(SqliteConnection databaseConnection, CancellationToken token = default(CancellationToken))
        {
            var tempFileStream = new TempFileStream();
            await using var fileDatabase = new SqliteConnection($"Data Source={tempFileStream.Path};");
            await fileDatabase.OpenAsync(token).ConfigureAwait(false);
            databaseConnection.BackupDatabase(fileDatabase);
            await fileDatabase.CloseAsync().ConfigureAwait(false);
            return tempFileStream;
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

        /// <summary>
        /// Gets the full path to a vault file by name.
        /// </summary>
        /// <param name="vaultName">The name of the vault (without extension).</param>
        /// <returns>The full file path to the vault.</returns>
        private static string GetVaultPath(string vaultName = null)
        {
            if (string.IsNullOrEmpty(vaultName))
                vaultName = DefaultVaultName;

            return System.IO.Path.ChangeExtension(System.IO.Path.Combine(NivoraStatics.NivoraApplicationDataPath, vaultName),
                DefaultVaultExtension);
        }

        /// <summary>
        /// Creates a new vault with the specified password and name.
        /// </summary>
        /// <param name="password">The password for the vault.</param>
        /// <param name="vaultName">The name of the vault.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>The created vault instance.</returns>
        public static Task<Vault> CreateNew(string password, string vaultName = null, CancellationToken token = default(CancellationToken))
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            return CreateVault(GetVaultPath(vaultName), password, token);
        }

        /// <summary>
        /// Opens an existing vault with the specified password and name.
        /// </summary>
        /// <param name="password">The password for the vault.</param>
        /// <param name="vaultName">The name of the vault.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>The opened vault instance, or null if not found.</returns>
        public static Task<Vault> OpenExisting(string password, string vaultName = null, CancellationToken token = default(CancellationToken))
        {
            return OpenVault(GetVaultPath(vaultName), password, token);
        }
    }
}