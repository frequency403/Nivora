using System.Net;
using Dapper;
using System.Text;
using DryIoc.ImTools;
using Microsoft.Data.Sqlite;
using Nivora.Core.Database.Models;
using Nivora.Core.Exceptions;
using Nivora.Core.Models;
using Nivora.Core.Streams;
using Serilog;

[module:DapperAot]

namespace Nivora.Core.Database
{
    /// <summary>
    /// Represents a secure vault for storing secrets in an encrypted SQLite database.
    /// </summary>
    public class Vault : IDisposable, IAsyncDisposable
    {
        private readonly ILogger _logger;
        private VaultParameters Parameters { get; set; }

        internal static Vault Empty(ILogger logger) => new(logger);
        
        private byte[] MasterPassword { get; set; }

        // Hide default constructor for controlled initialization
        private Vault(ILogger logger)
        {
            _logger = logger;
        }

        public string Name => System.IO.Path.GetFileNameWithoutExtension(Path.FullName);
        
        /// <summary>
        /// The file path of the vault.
        /// </summary>
        public FileInfo Path { get; private set; }

        /// <summary>
        /// The version of the vault.
        /// </summary>
        public VaultVersion Version => Parameters.Version;

        /// <summary>
        /// The SQLite connection to the vault database.
        /// </summary>
        public SqliteConnection Connection { get; private set; }

        /// <summary>
        /// Asynchronously disposes the vault and its database connection.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            await Connection.DisposeAsync();
        }

        /// <summary>
        /// Disposes the vault and its database connection.
        /// </summary>
        public void Dispose()
        {
            Connection.Dispose();
        }

        
        
        /// <summary>
        /// Retrieves a secret by name.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <returns>The secret if found, otherwise null.</returns>
        public async Task<Secret?> GetSecretAsync(string name)
        {
            return await Connection.QuerySingleOrDefaultAsync<Secret>(
                "SELECT * FROM Secrets WHERE Name = @Name",
                new { Name = name });
        }
        
        public async IAsyncEnumerable<Secret> GetAllSecretsAsync()
        {
            await foreach (var secret in Connection.QueryUnbufferedAsync<Secret>("SELECT * FROM Secrets"))
            {
                yield return secret;
            }
        }

        /// <summary>
        /// Adds a new secret to the vault.
        /// </summary>
        /// <param name="secret">The secret to add.</param>
        /// <returns>The added secret if successful, otherwise null.</returns>
        public async Task<Secret?> AddSecretAsync(Secret secret, CancellationToken cancellationToken = default)
        {
            var rowsAffected = await Connection.ExecuteAsync(
                "INSERT INTO Secrets (Name, Iv, Value) VALUES (@Name, @Iv, @Value)",
                secret) > 0;
            var saveSuccessful = await SaveChangesAsync(cancellationToken);
            if (rowsAffected && saveSuccessful)
                return await GetSecretAsync(secret.Name);
            return null;
        }

        /// <summary>
        /// Updates an existing secret in the vault.
        /// </summary>
        /// <param name="secret">The secret to update.</param>
        /// <returns>The updated secret if successful, otherwise null.</returns>
        public async Task<Secret?> UpdateSecretAsync(Secret secret, CancellationToken cancellationToken = default)
        {
            var rowsAffected = await Connection.ExecuteAsync(
                "UPDATE Secrets SET Iv = @Iv, Value = @Value, UpdatedAt = CURRENT_TIMESTAMP WHERE Name = @Name",
                secret) > 0;
            var saveSuccessful = await SaveChangesAsync(cancellationToken);
            if (rowsAffected && saveSuccessful)
                return await GetSecretAsync(secret.Name);
            return null;
        }

        /// <summary>
        /// Deletes a secret by name.
        /// </summary>
        /// <param name="name">The name of the secret to delete.</param>
        /// <returns>True if the secret was deleted, otherwise false.</returns>
        public async Task<bool> DeleteSecretAsync(string name, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(name))
                throw new ArgumentException("Name cannot be null or empty.", nameof(name));
            var hasAffectedAnyRows = await Connection.ExecuteAsync(
                "DELETE FROM Secrets WHERE Name = @Name",
                new { Name = name }) > 0;
            var saveSuccessful = await SaveChangesAsync(cancellationToken);
            
            return hasAffectedAnyRows && saveSuccessful;
        }

        private async Task<bool> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await Connection.CloseAsync();
                await using (var tempFileStream = await WriteDatabaseToFile(Connection, cancellationToken))
                {
                    Parameters.Content = await tempFileStream.ToArrayAsync(cancellationToken);
                    await Parameters.EncryptContent(MasterPassword);
                }
                await TlvStream.WriteParametersAndEncrypt(Parameters, Path, MasterPassword,
                    cancellationToken);
                var parameters = await TlvStream.ReadEncryptedStream(Path, MasterPassword, cancellationToken);
                if (parameters == null)
                {
                    _logger.Error("Failed to read vault parameters after writing.");
                    Path.Delete();
                    await DisposeAsync();
                    return false;
                }
                Connection = await ReadBinaryDatabaseToMemory(parameters.Content, cancellationToken);
            }
            catch (Exception e)
            {
                _logger.Error(e, "Error while updating vault");
                return false;
            }
            return true;
        }

        /// <summary>
        /// Opens an existing vault from disk, decrypts it, and loads it into memory.
        /// </summary>
        /// <param name="path">The file path to the vault.</param>
        /// <param name="password">The password to decrypt the vault.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>The opened Vault instance, or null if the file does not exist.</returns>
        private async Task<Vault> OpenVault(string path, byte[] password, CancellationToken token)
        {
            var fileInfo = new FileInfo(path);
            if (!fileInfo.Exists)
                throw new FileNotFoundException($"Vaultfile '{fileInfo.FullName}' not found.", fileInfo.FullName);
            var parameters = await TlvStream.ReadEncryptedStream(fileInfo, password, token);
            if (parameters == null)
                throw new InvalidOperationException("Failed to read vault parameters from the encrypted file.");
            var memoryDatabase = await ReadBinaryDatabaseToMemory(parameters.Content, token);
            return new Vault(_logger)
            {
                Path = fileInfo,
                Connection = memoryDatabase,
                Parameters = parameters,
                MasterPassword = password
            };
        }

        /// <summary>
        /// Creates a new vault at the specified path with the given password.
        /// </summary>
        /// <param name="path">The file path to create the vault at.</param>
        /// <param name="password">The password for the vault.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>The created Vault instance.</returns>
        private async Task<Vault> CreateVault(string path, byte[] password, CancellationToken token)
        {
            var fileInfo = new FileInfo(path);
            VaultFileExistsException.ThrowIfExists(fileInfo);
            if (!fileInfo.Directory?.Exists ?? true)
                fileInfo.Directory?.Create();

            var parameters = VaultParameters.Default;

            await using var memoryDatabase = new SqliteConnection("Data Source=:memory:");
            await memoryDatabase.OpenAsync(token);

            // Create tables and initial structure
            await using (var command = memoryDatabase.CreateCommand())
            {
                command.CommandText = Secret.CreateTableSql;
                await command.ExecuteNonQueryAsync(token);
            }

            await using (var databaseStream = await WriteDatabaseToFile(memoryDatabase, token))
            {
                databaseStream.Position = 0;
                parameters.Content = await databaseStream.ToArrayAsync(token);
            }
            await TlvStream.WriteParametersAndEncrypt(parameters, fileInfo, password, token);
            

            return new Vault(_logger)
            {
                Path = fileInfo,
                Connection = memoryDatabase,
                Parameters = parameters,
                MasterPassword = password
            };
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
            await fileDatabase.OpenAsync(token);
            databaseConnection.BackupDatabase(fileDatabase);
            await fileDatabase.CloseAsync();
            return tempFileStream;
        }

        private static async Task<SqliteConnection> ReadBinaryDatabaseToMemory(byte[] binaryDatabase,
            CancellationToken token = default(CancellationToken))
        {
            var memoryDatabase = new SqliteConnection("Data Source=:memory:");
            await memoryDatabase.OpenAsync(token);

            await using var tempFileStream = new TempFileStream();
            await tempFileStream.WriteAsync(binaryDatabase, token);
            await using var fileDatabase = new SqliteConnection($"Data Source={tempFileStream.Path};");
            await fileDatabase.OpenAsync(token);
            fileDatabase.BackupDatabase(memoryDatabase);
            await fileDatabase.CloseAsync();
            return memoryDatabase;
        }

        /// <summary>
        /// Shuffles the input bytes in the pattern 0, N-1, 1, N-2, ... up to a maximum of <paramref name="size" /> elements.
        /// If the input is shorter than <paramref name="size" />, uses only as many as are available.
        /// </summary>
        /// <param name="input">The input byte array to be permuted.</param>
        /// <param name="size">Maximum number of bytes to output.</param>
        /// <returns>Shuffled byte array.</returns>
        internal static byte[] ShuffleBytes(byte[] input, int size)
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
        internal byte[] GetBytesFromFilePath(string path, int count = 32)
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
        internal static string GetVaultPath(string? vaultName = null)
        {
            if (string.IsNullOrEmpty(vaultName))
                vaultName = NivoraStatics.DefaultVaultName;

            return System.IO.Path.ChangeExtension(System.IO.Path.Combine(NivoraStatics.NivoraApplicationDataPath, vaultName),
                NivoraStatics.DefaultVaultExtension);
        }

        /// <summary>
        /// Creates a new vault with the specified password and name.
        /// </summary>
        /// <param name="password">The password for the vault.</param>
        /// <param name="vaultName">The name of the vault.</param>
        /// <param name="token">A cancellation token.</param>
        /// <returns>The created vault instance.</returns>
        internal Task<Vault> CreateNew(byte[] password, string vaultName = null, CancellationToken token = default(CancellationToken))
        {
            if (password == null || password.Length == 0)
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
        internal Task<Vault> OpenExisting(byte[] password, string vaultName = null, CancellationToken token = default(CancellationToken))
        {
            return OpenVault(GetVaultPath(vaultName), password, token);
        }
    }
}