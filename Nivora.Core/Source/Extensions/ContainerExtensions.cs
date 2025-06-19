using System.Reflection;
using DryIoc;
using Nivora.Core.Factory;
using Nivora.Core.Interfaces;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace Nivora.Core.Extensions;

public static class ContainerExtensions
{
    public static IContainer AddCoreServices(this IContainer container)
    {
        ArgumentNullException.ThrowIfNull(container);
#if DEBUG
        var consoleLogLevelSwitch = new LoggingLevelSwitch
        {
            MinimumLevel = LogEventLevel.Fatal // Default log level
        };
#endif
        var fileLogLevelSwitch = new LoggingLevelSwitch
        {
            MinimumLevel = LogEventLevel.Verbose // Default file log level
        };
        var logFilePath = NivoraStatics.NivoraLogsPath;
        if (!Directory.Exists(logFilePath)) Directory.CreateDirectory(logFilePath);
        // Register core services here
        
        container.RegisterInstance<ILogger>(new LoggerConfiguration()
#if DEBUG
            .MinimumLevel.ControlledBy(consoleLogLevelSwitch)
            .WriteTo.Console(levelSwitch: consoleLogLevelSwitch)
#endif
            .WriteTo.File(Path.Combine(logFilePath, Path.ChangeExtension(Assembly.GetExecutingAssembly().FullName?.Split('.')[0].ToLower(), "log") ?? "nivora.log"), rollingInterval: RollingInterval.Day,
                levelSwitch: fileLogLevelSwitch)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "Nivora")
            .CreateLogger());
            
#if DEBUG
            container.RegisterInstance(consoleLogLevelSwitch, serviceKey:"ConsoleLogLevelSwitch");
#endif
                container.RegisterInstance(fileLogLevelSwitch, serviceKey: "FileLogLevelSwitch");
            container.Register<IVaultFactory, VaultFactory>(reuse: Reuse.Singleton);
        return container;
    }
}