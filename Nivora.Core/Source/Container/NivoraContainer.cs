using System.Diagnostics.CodeAnalysis;
using DryIoc.Microsoft.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Nivora.Core.Extensions;

namespace Nivora.Core.Container;

public static class NivoraContainer
{
    public static IServiceCollection Initialize()
    {
        return new ServiceCollection().AddCoreServices();
    }
    
    public static IServiceProvider Build(IServiceCollection services)
    {
        var container = new DryIoc.Container();
        return container.WithDependencyInjectionAdapter(services).BuildServiceProvider();
    }
}