using Nivora.Core.Database;

namespace Nivora.Core.Interfaces;

public interface IVaultFactory
{
    Task<Vault?> CreateAsync(byte[] password, string? vaultName, CancellationToken cancellationToken = default);
    Task<Vault?> OpenAsync(byte[] password, string? vaultName, CancellationToken cancellationToken = default);
}