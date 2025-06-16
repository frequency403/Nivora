using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace Nivora.Core.Extensions;

public static class ContainerExtensions
{
    public static IServiceCollection AddCoreServices(this IServiceCollection services)
    {
        var logLevelSwitch = new LoggingLevelSwitch
        {
            MinimumLevel = LogEventLevel.Information // Default log level
        };

        // Register core services here
        services.AddLogging(builder =>
        {
            builder.AddSerilog(new LoggerConfiguration()
                .MinimumLevel.ControlledBy(logLevelSwitch)
                .WriteTo.Console()
                .WriteTo.File("logs/nivora.log", rollingInterval: RollingInterval.Day)
                .Enrich.FromLogContext()
                .Enrich.WithProperty("Application", "Nivora")
                .CreateLogger(), true);
        });
        services.AddSingleton(logLevelSwitch);

        return services;
    }
}