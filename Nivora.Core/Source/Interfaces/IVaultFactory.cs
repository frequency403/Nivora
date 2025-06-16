using Nivora.Core.Database;

namespace Nivora.Core.Interfaces;

public interface IVaultFactory
{
    Task<Vault?> CreateAsync(string password, string? vaultName, CancellationToken cancellationToken = default);
    Task<Vault?> OpenAsync(string password, string? vaultName, CancellationToken cancellationToken = default);
}