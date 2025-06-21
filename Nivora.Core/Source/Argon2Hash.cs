using System.Security.Cryptography;
using System.Text;
using Nivora.Core.Models;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Nivora.Core;

public static class Argon2Hash
{
    private const int SaltSize = 12; // 96 bits
    private const int DefaultIterations = 3;
    private const int DefaultMemory = 65536; // 64 MB
    private const int DefaultParallelism = 1;
    private const int HashSize = 32; // 256 bits
    
    private static byte[] GenerateSalt(int size = SaltSize) => RandomNumberGenerator.GetBytes(size);
    public static Task<byte[]> HashBytesAsync(byte[] password) =>
        Task.Run(() => HashCore(password));
    
    public static byte[] HashBytes(byte[] password) =>
        HashCore(password);

    private static byte[] HashCore(byte[] password, int iterations = DefaultIterations, int memory = DefaultMemory,
        byte[]? salt = null)
    {
        if (password.Length == 0)
            throw new ArgumentException("Password cannot or empty.", nameof(password));
        var generator = new Argon2BytesGenerator();
        var parameters = new Argon2Parameters.Builder()
            .WithMemoryAsKB(memory)
            .WithIterations(iterations)
            .WithParallelism(Environment.ProcessorCount)
            .WithSalt(salt ?? GenerateSalt())
            .WithVersion(Argon2Parameters.Version13)
            .Build();
        generator.Init(parameters);
        var hash = new byte[HashSize];
        generator.GenerateBytes(password, hash);
        return hash;
    }
}