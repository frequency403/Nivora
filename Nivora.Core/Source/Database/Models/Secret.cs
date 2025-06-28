using System.Text;
using Nivora.Core.Models;

namespace Nivora.Core.Database.Models;

public record Secret
{
    internal const string CreateTableSql = """
                                           CREATE TABLE IF NOT EXISTS Secrets (
                                           Id INTEGER PRIMARY KEY AUTOINCREMENT,
                                           Name TEXT NOT NULL UNIQUE,
                                           Iv BLOB NOT NULL,
                                           Value BLOB NOT NULL,
                                           CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                                           UpdatedAt DATETIME
                                           );
                                           """;

    public int Id { get; set; } = 0;
    public string Name { get; set; } = string.Empty;
    public byte[] Iv { get; set; } = [];
    public byte[] Value { get; set; } = [];
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; } = null;

    public static async Task<Secret> CreateFromPlaintext(string name, string value, PasswordHash masterPassword)
    {
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Name cannot be null or empty.", nameof(name));
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException("Value cannot be null or empty.", nameof(value));


        var iv = Aes256.GenerateRandomIv();
        return new Secret
        {
            Name = name,
            Value = Aes256.Encrypt(Encoding.UTF8.GetBytes(value), masterPassword.Value, iv),
            Iv = iv
        };
    }
}