using CliFx;
using DryIoc;
using DryIoc.Microsoft.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Nivora.Core.Container;
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
                var services = NivoraContainer.Initialize();
                foreach (var type in commandTypes) 
                    services.AddTransient(type);
                
                return NivoraContainer.Build(services);
            })
            .Build();
        return await cliApp.RunAsync(args);
    }
}