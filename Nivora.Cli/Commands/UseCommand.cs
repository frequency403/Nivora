using Nivora.Cli.Commands.Arguments;
using Nivora.Core;
using Nivora.Core.Database;
using Nivora.Core.Database.Models;
using Nivora.Core.Enums;
using Nivora.Core.Interfaces;
using Org.BouncyCastle.Crypto;
using Serilog;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Nivora.Cli.Commands;

public class UseCommand(ILogger logger, IVaultFactory vaultFactory) : AsyncCommand<UseArguments>
{
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    public override async Task<int> ExecuteAsync(CommandContext context, UseArguments settings)
    {
        string password;
        FileInfo vaultFile = new FileInfo(Path.Combine(NivoraStatics.NivoraApplicationDataPath, settings?.VaultName ?? "vault"));
        if (!vaultFile.Exists)
        {
            logger.Information("No valid vault name provided. Listing all when available and force selection.");
            AnsiConsole.MarkupLine("[yellow]No valid vault name provided. Listing all available vaults.[/]");
            var vaults = ListVaultsCommand.GetVaultFiles();
            if (vaults.Length == 0)
            {
                logger.Error("No vaults found. Please create a vault first.");
                AnsiConsole.MarkupLine("[red]No vaults found. Please create a vault first.[/]");
                return 1;
            }
            vaultFile = await AnsiConsole.PromptAsync(
                new SelectionPrompt<FileInfo>()
                    .Title("Select a vault to use:")
                    .PageSize(10)
                    .MoreChoicesText("[grey](Move up and down to reveal more vaults)[/]")
                    .AddChoices(vaults),
                _cancellationTokenSource.Token);
        }

        if (string.IsNullOrWhiteSpace(settings.Password))
        {
            password = await AnsiConsole.PromptAsync(new TextPrompt<string>("Enter a password for the vault:")
                .PromptStyle("green")
                .Secret(), _cancellationTokenSource.Token);
        }
        else
        {
            password = settings.Password;
        }

        try
        {
            var vault = await vaultFactory.OpenAsync(password, vaultFile.Name, _cancellationTokenSource.Token);
            logger.Information("Vault '{VaultName}' opened successfully.", vaultFile.Name);
            AnsiConsole.MarkupLine($"[green]Vault '{vault.Name}' opened successfully![/]");
            AnsiConsole.Clear();
            var shouldExit = false;
            while (!shouldExit)
            {
                var secretName = settings.SecretName;
                var secretValue = settings.SecretValue;

                AnsiConsole.MarkupLine($"[blue]Using Vault {vault.Name}[/]");
                switch (await AnsiConsole.PromptAsync(new SelectionPrompt<VaultOperation>()
                            .Title("Select an operation:")
                            .PageSize(5)
                            .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                            .AddChoices(Enum.GetValues<VaultOperation>()), _cancellationTokenSource.Token))
                {
                    case VaultOperation.AddSecret:


                        if (string.IsNullOrWhiteSpace(secretName))
                        {
                            var secretNamePrompt = new TextPrompt<string>("Enter the name of the secret to add:")
                                .PromptStyle("green")
                                .ValidationErrorMessage("[red]Secret name cannot be empty.[/]")
                                .Validate(name =>
                                    string.IsNullOrWhiteSpace(name)
                                        ? ValidationResult.Error("Secret name cannot be empty.")
                                        : ValidationResult.Success());
                            secretName = await AnsiConsole.PromptAsync(secretNamePrompt);
                        }

                        if (string.IsNullOrWhiteSpace(secretValue))
                        {
                            var secretValuePrompt = new TextPrompt<string>("Enter the value of the secret:")
                                .PromptStyle("green")
                                .Secret()
                                .ValidationErrorMessage("[red]Secret value cannot be empty.[/]")
                                .Validate(value =>
                                    string.IsNullOrWhiteSpace(value)
                                        ? ValidationResult.Error("Secret value cannot be empty.")
                                        : ValidationResult.Success());
                            secretValue = await AnsiConsole.PromptAsync(secretValuePrompt);
                        }

                        var newSecret = await Secret.CreateFromPlaintext(secretName, secretValue, password);
                        var secret = await vault.AddSecretAsync(newSecret);
                        AnsiConsole.MarkupLine(secret is not null
                            ? $"[green]Secret '{secret.Name}' added successfully![/]"
                            : "[red]Failed to add secret.[/]");
                        break;
                    case VaultOperation.ListSecrets:
                        var table = new Table().AddColumns("ID", "Name", "Created At", "Updated At")
                            .RoundedBorder()
                            .Title(new TableTitle($"[blue]Secrets in Vault[/] [gray]\"{vault.Name}\"[/]"));
                        await AnsiConsole.Live(table).StartAsync(async ctx =>
                        {
                            var anySecrets = false;
                            await foreach(var vaultSecret in vault.GetAllSecretsAsync())
                            {
                                table.AddRow(
                                    vaultSecret.Id.ToString(),
                                    vaultSecret.Name,
                                    vaultSecret.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"),
                                    vaultSecret.UpdatedAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A");
                                ctx.Refresh();
                                anySecrets = true;
                            }

                            if (!anySecrets)
                            {
                                AnsiConsole.MarkupLine("[red]No secret found in vault.[/]");
                            }
                        });
                        var input = await AnsiConsole.AskAsync<string>("Press C to clear and any other key to continue...");
                        if (input?.ToUpperInvariant() == "C")
                        {
                            AnsiConsole.Clear();
                        }
                        break;
                    case VaultOperation.Exit:
                        shouldExit = true;
                        AnsiConsole.MarkupLine("[yellow]Exiting nivora. Goodbye![/]");
                        break;
                    case VaultOperation.RemoveSecret:
                    case VaultOperation.UpdateSecret:
                    case VaultOperation.GetSecret:
                    default:
                        break;
                }
            }

        }
        catch (InvalidCipherTextException)
        {
            AnsiConsole.MarkupLine("[red]Invalid password provided. Exiting.[/]");
            return 1;
        }
        catch (FileNotFoundException)
        {
            AnsiConsole.MarkupLine($"[red]Vault file '{vaultFile.Name}' not found.[/]");
            if (string.IsNullOrWhiteSpace(settings.VaultName))
            {
                AnsiConsole.MarkupLine("[red]Please specify a vault by using the [bold]-v <VAULT_NAME>[/] flag or create one by calling nivora with the [bold]init[/] command.[/]");
            }
        }
        catch (Exception e)
        {
            AnsiConsole.WriteException(e);
            return 1;
        }
        return 0;
    }
}