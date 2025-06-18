using DryIoc;
using Spectre.Console.Cli;

namespace Nivora.Cli.Infrastructure;

public sealed class DryIocResolver(IContainer container) : ITypeResolver, IDisposable
{
    private readonly IContainer _container = container ?? throw new ArgumentNullException(nameof(container));

    public void Dispose()
    {
        _container.Dispose();
    }

    public object? Resolve(Type? type)
    {
        return _container.Resolve(type, IfUnresolved.Throw);
    }
}