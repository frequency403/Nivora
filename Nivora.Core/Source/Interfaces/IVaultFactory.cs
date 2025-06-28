using Nivora.Core.Database;
using Nivora.Core.Models;

namespace Nivora.Core.Interfaces;

public interface IVaultFactory
{
    Task<Vault?> CreateAsync(PasswordHash password, string? vaultName, CancellationToken cancellationToken = default);
    Task<Vault?> OpenAsync(PasswordHash password, string? vaultName, CancellationToken cancellationToken = default);
}