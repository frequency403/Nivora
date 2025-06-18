using System.Diagnostics;
using Nivora.Cli.Commands.Arguments;
using Nivora.Core.Database;
using Nivora.Core.Exceptions;
using Serilog;
using Spectre.Console;
using Spectre.Console.Cli;

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
            logger.Error("Master password cannot be null or empty.");
            return 1;
        }

        logger.Information("Initializing vault '{VaultName}'...", arguments.VaultName);
        AnsiConsole.WriteLine("Initializing vault '{0}'...", arguments.VaultName);
        try
        {
            var stopwatch = Stopwatch.StartNew();
            await using var vault = await Vault.CreateNew(arguments.Password, arguments.VaultName, cancellationToken);
            stopwatch.Stop();
            if (vault == null)
            {
                logger.Error("Failed to create vault. Elapsed time: {ElapsedTime} s",
                    stopwatch.Elapsed.TotalSeconds);
                return 1;
            }

            logger.Information("Created vault '{VaultName}' with version {Version} in {ElapsedTime} s",
                vault.Path, vault.Version, stopwatch.Elapsed.TotalSeconds);
        }
        catch (VaultFileExistsException ex)
        {
            logger.Error(ex,
                "Vault file '{VaultName}' already exists. Please choose a different name or delete the existing file.",
                arguments.VaultName);
        }
        catch (Exception e)
        {
            logger.Error(e, "Failed to create vault '{VaultName}'", arguments.VaultName);
        }

        return 0;
    }
}