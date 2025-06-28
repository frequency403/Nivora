using System.Text;
using Nivora.Cli.Commands.Arguments;
using Nivora.Core;
using Nivora.Core.Database;
using Nivora.Core.Database.Models;
using Nivora.Core.Enums;
using Nivora.Core.Interfaces;
using Nivora.Core.Models;
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
        var vaultFile =
            new FileInfo(Path.Combine(NivoraStatics.NivoraApplicationDataPath, settings.VaultName ?? "vault"));
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

        if (settings?.Password.Length == 0)
        {
            settings.Password = await PasswordHash.FromPlainTextAsync(await AnsiConsole.PromptAsync(
                new TextPrompt<string>("Enter a password for the vault:")
                    .PromptStyle("green").Secret()));
        }


        try
        {
            await using var vault = await AnsiConsole
                .Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.SimpleDotsScrolling)
                .StartAsync("Opening vault...",
                    async _ => await vaultFactory.OpenAsync(settings.Password, vaultFile.Name,
                        _cancellationTokenSource.Token));
            logger.Information("Vault '{VaultName}' opened successfully.", vaultFile.Name);
            AnsiConsole.MarkupLine($"[green]Vault '{vault.Name}' opened successfully![/]");
            AnsiConsole.Clear();
            var shouldExit = false;
            while (!shouldExit)
            {
                var secretName = settings.SecretName;
                var secretValue = settings.SecretValue;

                AnsiConsole.MarkupLine($"[blue]Using Vault {vault.Name}[/]");
                settings.Operation ??= await AnsiConsole.PromptAsync(new SelectionPrompt<VaultOperation>()
                    .Title("Select an operation:")
                    .PageSize(5)
                    .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                    .AddChoices(Enum.GetValues<VaultOperation>()), _cancellationTokenSource.Token);
                switch (settings.Operation)
                {
                    case VaultOperation.AddSecret:


                        if (string.IsNullOrWhiteSpace(secretName))
                        {
                            secretName = await PromptForSecretNameAsync(_cancellationTokenSource.Token);
                        }

                        if (string.IsNullOrWhiteSpace(secretValue))
                        {
                            secretValue = await PromptForSecretValueAsync(_cancellationTokenSource.Token);
                        }

                        var newSecret = await Secret.CreateFromPlaintext(secretName, secretValue, settings.Password);
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
                            await foreach (var vaultSecret in vault.GetAllSecretsAsync())
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
                        var input = await AnsiConsole.AskAsync<string>(
                            "Press C to clear and any other key to continue...");
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
                        var secretToRemove = await AnsiConsole.PromptAsync(new SelectionPrompt<Secret>()
                                .Title("Select a secret to remove:")
                                .PageSize(10)
                                .MoreChoicesText("[grey](Move up and down to reveal more secrets)[/]")
                                .AddChoices(vault.GetAllSecretsAsync().ToBlockingEnumerable()),
                            _cancellationTokenSource.Token);
                        if (!await ConfirmPasswordAsync(vault.VerifyPassword, _cancellationTokenSource.Token))
                        {
                            AnsiConsole.MarkupLine("[red]Password confirmation failed. Aborting removal.[/]");
                            break;
                        }

                        var removed =
                            await vault.DeleteSecretAsync(secretToRemove.Name, _cancellationTokenSource.Token);
                        AnsiConsole.MarkupLine(
                            removed
                                ? $"[green]Secret '{secretToRemove.Name}' removed successfully![/]"
                                : "[red]Failed to remove secret. It may not exist.[/]");
                        break;
                    case VaultOperation.GetSecret:
                        var secretToGet = await AnsiConsole.PromptAsync(new SelectionPrompt<Secret>()
                                .Title("Select a secret to retrieve:")
                                .PageSize(10)
                                .MoreChoicesText("[grey](Move up and down to reveal more secrets)[/]")
                                .AddChoices(vault.GetAllSecretsAsync().ToBlockingEnumerable()),
                            _cancellationTokenSource.Token);
                        if (!await ConfirmPasswordAsync(vault.VerifyPassword, _cancellationTokenSource.Token))
                        {
                            AnsiConsole.MarkupLine("[red]Password confirmation failed. Aborting retrieval.[/]");
                            break;
                        }

                        var retrievedSecret = await vault.GetSecretAsync(secretToGet.Name);
                        if (retrievedSecret is null)
                        {
                            AnsiConsole.MarkupLine("[red]Failed to retrieve secret.[/]");
                            break;
                        }

                        var secretTable = new Table()
                            .AddColumns("Name", "Value", "Created At", "Updated At")
                            .RoundedBorder()
                            .Title(new TableTitle($"[blue]Retrieved Secret[/] [gray]\"{retrievedSecret.Name}\"[/]"));
                        secretTable.AddRow(retrievedSecret.Name,
                            Encoding.UTF8.GetString(Aes256.Decrypt(retrievedSecret.Value, settings.Password.Value,
                                retrievedSecret.Iv)),
                            retrievedSecret.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"),
                            retrievedSecret.UpdatedAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A");
                        AnsiConsole.Write(secretTable);
                        var inputGet =
                            await AnsiConsole.AskAsync<string?>("Press C to clear and any other key to continue...");
                        if (inputGet?.ToUpperInvariant() == "C")
                        {
                            AnsiConsole.Clear();
                        }

                        break;
                    case VaultOperation.UpdateSecret:
                        var secretToUpdate = await AnsiConsole.PromptAsync(new SelectionPrompt<Secret>()
                                .Title("Select a secret to update:")
                                .PageSize(10)
                                .MoreChoicesText("[grey](Move up and down to reveal more secrets)[/]")
                                .AddChoices(vault.GetAllSecretsAsync().ToBlockingEnumerable()),
                            _cancellationTokenSource.Token);
                        if (!await ConfirmPasswordAsync(vault.VerifyPassword, _cancellationTokenSource.Token))
                        {
                            AnsiConsole.MarkupLine("[red]Password confirmation failed. Aborting update.[/]");
                            break;
                        }

                        var whatToUpdate = await AnsiConsole.PromptAsync(new SelectionPrompt<string>()
                            .Title($"What do you want to update in secret '{secretToUpdate.Name}'?")
                            .PageSize(2)
                            .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                            .AddChoices(nameof(Secret.Name), nameof(Secret.Value)), _cancellationTokenSource.Token);
                        switch (whatToUpdate)
                        {
                            case nameof(Secret.Name):
                                var newName = await PromptForSecretNameAsync(_cancellationTokenSource.Token);
                                if (string.IsNullOrWhiteSpace(newName))
                                {
                                    AnsiConsole.MarkupLine("[red]Secret name cannot be empty. Aborting update.[/]");
                                    break;
                                }

                                secretToUpdate.Name = newName;
                                secretToUpdate =
                                    await vault.UpdateSecretAsync(secretToUpdate, _cancellationTokenSource.Token);
                                AnsiConsole.MarkupLine(secretToUpdate is null
                                    ? "[red]Failed to update secret.[/]"
                                    : $"[green]Secret '{secretToUpdate.Name}' updated successfully![/]");
                                break;
                            case nameof(Secret.Value):
                                var newValue = await PromptForSecretValueAsync(_cancellationTokenSource.Token);
                                if (string.IsNullOrWhiteSpace(newValue))
                                {
                                    AnsiConsole.MarkupLine("[red]Secret value cannot be empty. Aborting update.[/]");
                                    break;
                                }

                                secretToUpdate.Value = Aes256.Encrypt(Encoding.UTF8.GetBytes(newValue),
                                    settings.Password.Value, secretToUpdate.Iv);
                                secretToUpdate =
                                    await vault.UpdateSecretAsync(secretToUpdate, _cancellationTokenSource.Token);
                                AnsiConsole.MarkupLine(secretToUpdate is null
                                    ? "[red]Failed to update secret.[/]"
                                    : $"[green]Secret '{secretToUpdate.Name}' updated successfully![/]");
                                break;
                        }

                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(VaultOperation));
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
                AnsiConsole.MarkupLine(
                    "[red]Please specify a vault by using the [bold]-v <VAULT_NAME>[/] flag or create one by calling nivora with the [bold]init[/] command.[/]");
            }
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLine("[red]An error occurred while trying to open the vault:[/] " + e.Message);
#if DEBUG
            AnsiConsole.WriteException(e);
#endif
            return 1;
        }

        return 0;
    }

    private async ValueTask<bool> ConfirmPasswordAsync(Func<PasswordHash, bool> verifyPasswordFunc,
        CancellationToken cancellationToken)
    {
        var password = await AnsiConsole.PromptAsync(new TextPrompt<string>("Confirm your password:")
            .PromptStyle("red")
            .Secret()
            .ValidationErrorMessage("[red]Wrong or invalid password.[/]")
            .Validate(password =>
                !string.IsNullOrWhiteSpace(password) &&
                verifyPasswordFunc(PasswordHash.FromPlainText(password))
                    ? ValidationResult.Error("Wrong or invalid password.")
                    : ValidationResult.Success()), cancellationToken);
        return !string.IsNullOrWhiteSpace(password);
    }

    private async ValueTask<string> PromptForSecretNameAsync(CancellationToken cancellationToken)
    {
        return await AnsiConsole.PromptAsync(new TextPrompt<string>("Enter the name of the secret:")
            .PromptStyle("green")
            .ValidationErrorMessage("[red]Secret name cannot be empty.[/]")
            .Validate(name => string.IsNullOrWhiteSpace(name)
                ? ValidationResult.Error("Secret name cannot be empty.")
                : ValidationResult.Success()), cancellationToken);
    }

    private async ValueTask<string> PromptForSecretValueAsync(CancellationToken cancellationToken)
    {
        return await AnsiConsole.PromptAsync(new TextPrompt<string>("Enter the value of the secret:")
            .PromptStyle("green")
            .Secret()
            .ValidationErrorMessage("[red]Secret value cannot be empty.[/]")
            .Validate(value => string.IsNullOrWhiteSpace(value)
                ? ValidationResult.Error("Secret value cannot be empty.")
                : ValidationResult.Success()), cancellationToken);
    }
}