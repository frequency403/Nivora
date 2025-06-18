using Serilog;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Nivora.Cli.Commands;
public class ListVaultsCommand(ILogger logger) : Command
{
    private static FileInfo[] GetVaultFiles(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            AnsiConsole.WriteLine("No vaults found.");
            return [];
        }
        AnsiConsole.WriteLine("Listing available vaults...");
        return directory.GetFiles("*.niv");
    }
    

    public override int Execute(CommandContext context)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nivora");
        
        var vaultFiles = GetVaultFiles(path);
        if (vaultFiles.Length == 0)
        {
            logger.Information("No vaults found in the directory '{Path}'.", path);
            
            AnsiConsole.WriteLine("No vaults found.");
            return 0;
        }
        logger.Information("Available vaults in '{Path}':", path);
        AnsiConsole.WriteLine($"Available vaults in '{path}':");
        
        const int width = 3;
        foreach (var file in vaultFiles.Select((info, i) => new { Info = info, Index = i }))
        {
            var indexStr = file.Index.ToString();
            var pad = width - indexStr.Length;
            var padLeft = pad / 2 + indexStr.Length;
            var centered = indexStr.PadLeft(padLeft).PadRight(width);
            AnsiConsole.WriteLine($"- [{centered}] {file.Info.Name} (Last modified: {file.Info.LastWriteTime})");
        }

        return 0;
    }
}