using Microsoft.Extensions.DependencyInjection;
using Nivora.Core.Factory;
using Nivora.Core.Interfaces;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace Nivora.Core.Extensions;

public static class ContainerExtensions
{
    public static IServiceCollection AddCoreServices(this IServiceCollection services)
    {
#if DEBUG
        var consoleLogLevelSwitch = new LoggingLevelSwitch
        {
            MinimumLevel = LogEventLevel.Fatal // Default log level
        };
#endif
        var fileLogLevelSwitch = new LoggingLevelSwitch
        {
            MinimumLevel = LogEventLevel.Information // Default file log level
        };
        var logFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nivora", "logs");
        if (!Directory.Exists(logFilePath)) Directory.CreateDirectory(logFilePath);
        // Register core services here
        return services.AddLogging(builder =>
            {
                builder.AddSerilog(new LoggerConfiguration()
#if DEBUG
                    .MinimumLevel.ControlledBy(consoleLogLevelSwitch)
                    .WriteTo.Console(levelSwitch: consoleLogLevelSwitch)
#endif
                    .WriteTo.File(Path.Combine(logFilePath, "nivora.log"), rollingInterval: RollingInterval.Day,
                        levelSwitch: fileLogLevelSwitch)
                    .Enrich.FromLogContext()
                    .Enrich.WithProperty("Application", "Nivora")
                    .CreateLogger(), true);
            })
#if DEBUG
            .AddKeyedSingleton("ConsoleLogLevelSwitch", consoleLogLevelSwitch)
#endif
            .AddKeyedSingleton("FileLogLevelSwitch", fileLogLevelSwitch)
            .AddSingleton<IVaultFactory, VaultFactory>();
    }
}