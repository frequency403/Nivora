using System.Diagnostics;
using Nivora.Cli.Commands.Arguments;
using Nivora.Core.Database;
using Nivora.Core.Exceptions;
using Serilog;
using Spectre.Console;
using Spectre.Console.Cli;
using Spectre.Console.Extensions;

namespace Nivora.Cli.Commands;

public class InitCommand(ILogger logger) : AsyncCommand<BaseArguments>
{
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    public override async Task<int> ExecuteAsync(CommandContext context, BaseArguments arguments)
    {
        var cancellationToken = _cancellationTokenSource.Token;

        if (string.IsNullOrEmpty(arguments.VaultName))
        {
            logger.Error("Vault name cannot be null or empty.");
            return 1;
        }

        if (string.IsNullOrEmpty(arguments.Password))
        {
            arguments.Password = await AnsiConsole.PromptAsync(new TextPrompt<string>($"Enter a password for your vault [red]\"{arguments.VaultName}\"[/]:").PromptStyle("green").Secret(), cancellationToken);
        }
        
        try
        {
            logger.Information("Initializing vault '{VaultName}'...", arguments.VaultName);
            AnsiConsole.Write("Initializing vault '{0}'", arguments.VaultName);
            var stopwatch = Stopwatch.StartNew();
            await using var vault = await Vault.CreateNew(arguments.Password, arguments.VaultName, cancellationToken).Spinner(Spinner.Known.SimpleDotsScrolling);
            stopwatch.Stop();
            AnsiConsole.WriteLine();
            logger.Information("Created vault '{VaultName}' with version {Version} in {ElapsedTime} s",
                vault.Path, vault.Version, stopwatch.Elapsed.TotalSeconds);
            AnsiConsole.MarkupLine($"[green]Vault '{arguments.VaultName}' created successfully in {stopwatch.Elapsed.TotalSeconds:N3} s![/]");
        }
        catch (VaultFileExistsException ex)
        {
            logger.Error(ex,
                "Vault file '{VaultName}' already exists. Please choose a different name or delete the existing file.",
                arguments.VaultName);
            AnsiConsole.MarkupLine($"[red]Vault file '{arguments.VaultName}' already exists.[/]");
        }
        catch (Exception e)
        {
            logger.Error(e, "Failed to create vault '{VaultName}'", arguments.VaultName);
            AnsiConsole.MarkupLine($"[red]Failed to create vault '{arguments.VaultName}': {e.Message}[/]");
        }

        return 0;
    }
}