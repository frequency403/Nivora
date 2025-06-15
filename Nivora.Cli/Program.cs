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
        Console.CancelKeyPress += (sender, eventArgs) =>
        {
            eventArgs.Cancel = true; // Prevent the process from terminating immediately
            Cts.Cancel(); // Trigger cancellation
        };
        
        var stopWatch = System.Diagnostics.Stopwatch.StartNew();
        await using var vault = await Vault.CreateNew("yourmomghey", null, Cts.Token);
        stopWatch.Stop();
        
        if (vault == null)
        {
            Console.WriteLine("Failed to create vault. Elapsed time: {0} s", stopWatch.Elapsed.TotalSeconds);
        }
        Console.WriteLine("Created {0} in {1} s",vault?.Version, stopWatch.Elapsed.TotalSeconds);
    }
}