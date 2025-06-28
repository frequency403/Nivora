using System.Text;

namespace Nivora.Core.Models;

public readonly record struct PasswordHash
{
    public readonly byte[] Value;
    public int Length => Value.Length;
    private PasswordHash(byte[] password) => Value = password;
    public static PasswordHash Empty => new();
    public static PasswordHash FromPlainText(string plainPassword) => new(Argon2Hash.HashBytes(Encoding.UTF8.GetBytes(plainPassword)));
    public static async Task<PasswordHash> FromPlainTextAsync(string plainPassword) => new(await Argon2Hash.HashBytesAsync(Encoding.UTF8.GetBytes(plainPassword)));
    public bool SequenceEqual(PasswordHash other)
    {
        if (Value.Length != other.Value.Length)
            return false;
        return !Value.Where((t, i) => t != other.Value[i]).Any();
    }
}