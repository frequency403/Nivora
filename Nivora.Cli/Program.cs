using Nivora.Core;
using Nivora.Core.Database;
using Nivora.Core.Models;

namespace Nivora.Cli;

class Program
{
    private static readonly CancellationTokenSource Cts = new();
    static async Task Main(string[] args)
    {
        Cts.Token.Register(() =>
        {
            Console.WriteLine("Exiting...");
        });
        await using var vault = await Vault.CreateNew("yourmomghey", null, Cts.Token);
        Console.WriteLine(vault?.Version);
        
        if (vault == null)
        {
            Console.WriteLine("Failed to create vault.");
        }
    }
}