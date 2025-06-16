using System.Diagnostics;
using CliFx;
using CliFx.Attributes;
using CliFx.Infrastructure;
using Microsoft.Extensions.Logging;
using Nivora.Core.Database;
using Nivora.Core.Exceptions;

namespace Nivora.Cli.Commands;
[Command("init", Description = "Initializes a new vault.")]
public class InitCommand(ILogger<InitCommand> logger) : ICommand
{
    [CommandOption("vault-name", 'n', Description = "The name of the vault file.", IsRequired = false)]
    public string? VaultName { get; set; } = "vault";
    
    [CommandOption("password", 'p', Description = "The master password for the vault.", IsRequired = true)]
    public string? Password { get; set; } = null;
    
    public async ValueTask ExecuteAsync(IConsole console)
    {
        var cancellationToken = console.RegisterCancellationHandler();
        
        if (string.IsNullOrEmpty(VaultName))
        {
            logger.LogError("Vault name cannot be null or empty.");
            return;
        }
        
        if (string.IsNullOrEmpty(Password))
        {
            logger.LogError("Master password cannot be null or empty.");
            return;
        }
        logger.LogInformation("Initializing vault '{VaultName}'...", VaultName);
        try
        {
            var stopwatch = Stopwatch.StartNew();
            await using var vault = await Vault.CreateNew(Password, VaultName, cancellationToken);
            stopwatch.Stop();
            if (vault == null)
            {
                logger.LogError("Failed to create vault. Elapsed time: {ElapsedTime} s", stopwatch.Elapsed.TotalSeconds);
                return;
            }

            logger.LogInformation("Created vault '{VaultName}' with version {Version} in {ElapsedTime} s",
                vault.Path, vault.Version, stopwatch.Elapsed.TotalSeconds);
        }
        catch (VaultFileExistsException ex)
        {
            logger.LogError(ex, "Vault file '{VaultName}' already exists. Please choose a different name or delete the existing file.", VaultName);
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to create vault '{VaultName}'", VaultName);
        }
    }
}