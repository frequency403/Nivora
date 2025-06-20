using System.Text;
using Nivora.Core.Models;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nivora.Core;

public static class Argon2Hash
{

    public static Task<byte[]> HashBytes(byte[] password, int iterations = 3, int memory = 65536, int parallelism = 1,
        byte[]? salt = null)
    {
        return HashCore(password, iterations, memory, parallelism, salt);
    }
    
    public static Task<byte[]> HashBytes(byte[] password, VaultParameters parameters) => HashCore(password, parameters);

    private static async Task<byte[]> HashCore(byte[] password, VaultParameters parameters)
    {
        if (password == null || password.Length == 0)
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        if (parameters.Salt == null || parameters.Salt.Length == 0)
            throw new InvalidOperationException("Salt must be set before hashing.");
        
        var generator = new Argon2BytesGenerator();
        var argon2Parameters = new Argon2Parameters.Builder()
            .WithMemoryAsKB(parameters.Argon2Memory)
            .WithIterations(parameters.Argon2Iterations)
            .WithParallelism(parameters.Argon2Parallelism)
            .WithSalt(parameters.Salt)
            .WithVersion(Argon2Parameters.Version13)
            .Build();
        generator.Init(argon2Parameters);
        var hash = new byte[32]; // 256 bits
        await Task.Run(() => generator.GenerateBytes(password, hash));
        return hash;
    }
    
    private static async Task<byte[]> HashCore(byte[] password, int iterations, int memory, int parallelism,
        byte[]? salt)
    {
        if (password.Length == 0)
            throw new ArgumentException("Password cannot or empty.", nameof(password));
        salt ??= Salt.Generate().Bytes;
        var generator = new Argon2BytesGenerator();
        var parameters = new Argon2Parameters.Builder()
            .WithMemoryAsKB(memory)
            .WithIterations(iterations)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .WithVersion(Argon2Parameters.Version13)
            .Build();
        generator.Init(parameters);
        var hash = new byte[32]; // 256 bits
        await Task.Run(() => generator.GenerateBytes(password, hash));
        return hash;
    }
}