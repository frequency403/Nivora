using System.Text;
using Nivora.Core.Models;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nivora.Core;

public static class Argon2Hash
{
    public static async Task<string> HashBase64(string password, int iterations = 3, int memory = 65536, int parallelism = 1) => Convert.ToBase64String(await HashCore(password, iterations, memory, parallelism));
    public static Task<byte[]> HashBytes(string password, int iterations = 3, int memory = 65536, int parallelism = 1) => HashCore(password, iterations, memory, parallelism);
    private static async Task<byte[]> HashCore(string password, int iterations, int memory, int parallelism)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));

        var generator = new Argon2BytesGenerator();
        var parameters = new Argon2Parameters.Builder()
            .WithMemoryAsKB(memory)
            .WithIterations(iterations)
            .WithParallelism(parallelism)
            .WithSalt(Salt.Generate().Bytes)
            .WithVersion(Argon2Parameters.Version13)
            .Build();
        generator.Init(parameters);
        var hash = new byte[32]; // 256 bits
        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        await Task.Run(() => generator.GenerateBytes(passwordBytes, hash));
        return hash;
    }
}