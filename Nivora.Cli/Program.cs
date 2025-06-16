using CliFx;
using Microsoft.Extensions.DependencyInjection;
using Nivora.Core.Extensions;

namespace Nivora.Cli;

internal class Program
{
    private static readonly CancellationTokenSource Cts = new();

    private static async Task<int> Main(string[] args)
    {
        var cliApp = new CliApplicationBuilder()
            .AddCommandsFromThisAssembly()
            .SetExecutableName("Nivora CLI")
            .SetDescription("Nivora CLI - A command line interface for Nivora, a secure vault for your secrets.")
            .SetVersion("1.0.0")
            .UseTypeActivator(commandTypes =>
            {
                var services = new ServiceCollection().AddCoreServices();

                // Register services

                // 

                // Register commands
                foreach (var commandType in commandTypes)
                    services.AddTransient(commandType);

                return services.BuildServiceProvider();
            })
            .Build();
        return await cliApp.RunAsync(args);
    }
}