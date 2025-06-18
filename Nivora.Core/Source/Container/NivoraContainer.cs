using DryIoc;
using Nivora.Core.Extensions;

namespace Nivora.Core.Container;

public static class NivoraContainer
{
    public static IContainer CreateDryIocContainer()
    {
        return new DryIoc.Container().AddCoreServices();
    }
    
}