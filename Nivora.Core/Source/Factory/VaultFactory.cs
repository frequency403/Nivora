using Nivora.Core.Database;
using Nivora.Core.Interfaces;
using Nivora.Core.Models;
using Serilog;

namespace Nivora.Core.Factory;

public class VaultFactory(ILogger logger) : IVaultFactory
{
    public Task<Vault?> CreateAsync(PasswordHash password, string? vaultName, CancellationToken cancellationToken = default)
    {
        var vault = Vault.Empty(logger);
        return vault.CreateNew(password, vaultName, cancellationToken);
    }
    
    public Task<Vault?> OpenAsync(PasswordHash password, string? vaultName, CancellationToken cancellationToken = default)
    {
        var vault = Vault.Empty(logger);
        return vault.OpenExisting(password, vaultName, cancellationToken);
    }
}