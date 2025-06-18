using Nivora.Core.Database;
using Nivora.Core.Interfaces;
using Serilog;

namespace Nivora.Core.Factory;

public class VaultFactory(ILogger logger) : IVaultFactory
{
    public Task<Vault?> CreateAsync(string password, string? vaultName, CancellationToken cancellationToken = default)
    {
        return Vault.CreateNew(password, vaultName, cancellationToken);
    }
    
    public Task<Vault?> OpenAsync(string password, string? vaultName, CancellationToken cancellationToken = default)
    {
        return Vault.OpenExisting(password, vaultName, cancellationToken);
    }
}