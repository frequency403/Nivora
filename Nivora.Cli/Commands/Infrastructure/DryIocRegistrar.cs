using DryIoc;
using Spectre.Console.Cli;

namespace Nivora.Cli.Commands.Infrastructure;

public class DryIocRegistrar(IContainer? container) : ITypeRegistrar
{
    public IContainer Container { get; } = container ?? new Container();

    public void Register(Type service, Type implementation)
    {
        Container.Register(service, implementation);
    }

    public void RegisterInstance(Type service, object implementation)
    {
        Container.RegisterInstance(service, implementation);
    }

    public void RegisterLazy(Type service, Func<object> factory)
    {
        Container.RegisterDelegate(_ => factory);
    }

    public ITypeResolver Build()
    {
        return new DryIocResolver(Container);
    }
}