using Nivora.Cli.Commands;
using Nivora.Cli.Infrastructure;
using Nivora.Core.Container;
using Spectre.Console.Cli;

namespace Nivora.Cli;

internal class Program
{
    private static readonly CancellationTokenSource Cts = new();

    private static async Task<int> Main(string[] args)
    {
        var app = new CommandApp<UseCommand>(new DryIocRegistrar(NivoraContainer.CreateDryIocContainer()));
        app.Configure(config =>
        {
            config.AddCommand<ListVaultsCommand>("list")
                .WithDescription("Lists all available vaults.")
                .WithExample("list");
            config.AddCommand<InitCommand>("init")
                .WithDescription("Initializes the Nivora vault with a password.")
                .WithExample("init", "-p", "your_password")
                .WithExample("init", "-p", "your_password", "--vaultName", "MyVault");
        });
        
        return await app.RunAsync(args);
    }
}