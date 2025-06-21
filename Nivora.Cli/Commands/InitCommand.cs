using System.Diagnostics;
using Nivora.Cli.Commands.Arguments;
using Nivora.Core;
using Nivora.Core.Database;
using Nivora.Core.Exceptions;
using Nivora.Core.Interfaces;
using Org.BouncyCastle.Crypto;
using Serilog;
using Spectre.Console;
using Spectre.Console.Cli;
using Spectre.Console.Extensions;

namespace Nivora.Cli.Commands;

public class InitCommand(ILogger logger, IVaultFactory vaultFactory) : AsyncCommand<BaseArguments>
{
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    public override async Task<int> ExecuteAsync(CommandContext context, BaseArguments arguments)
    {
        var cancellationToken = _cancellationTokenSource.Token;
        arguments.Password ??= [];
        if (string.IsNullOrEmpty(arguments.VaultName))
        {
            logger.Error("Vault name cannot be null or empty.");
            return 1;
        }
        
        try
        {
            if (arguments.Password.Length == 0)
            {
                arguments.Password = await Argon2Hash.HashBytesAsync(PasswordConverter.Utf8.Convert((await AnsiConsole.PromptAsync(new TextPrompt<string>($"Enter a password for your vault [red]\"{arguments.VaultName}\"[/]:").PromptStyle("green").Secret(), cancellationToken)).ToCharArray()));
            }
            
            logger.Information("Initializing vault '{VaultName}'...", arguments.VaultName);
            AnsiConsole.Write("Initializing vault '{0}'", arguments.VaultName);
            var stopwatch = Stopwatch.StartNew();
            await using var vault = await AnsiConsole
                .Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.SimpleDotsScrolling)
                .StartAsync("Creating vault...", async _ => await vaultFactory.CreateAsync(arguments.Password, arguments.VaultName, cancellationToken));
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
            return 1;
        }
        catch (Exception e)
        {
            logger.Error(e, "Failed to create vault '{VaultName}'", arguments.VaultName);
            AnsiConsole.MarkupLine($"[red]Failed to create vault '{arguments.VaultName}': {e.Message}[/]");
            #if DEBUG
            AnsiConsole.WriteException(e);
            #endif
            return 1;
        }

        return 0;
    }
}