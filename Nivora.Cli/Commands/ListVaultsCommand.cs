using Nivora.Core;
using Serilog;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Nivora.Cli.Commands;
public class ListVaultsCommand(ILogger logger) : Command
{
    public static FileInfo[] GetVaultFiles()
    {
        var directory = new DirectoryInfo(NivoraStatics.NivoraApplicationDataPath);
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
        var vaultFiles = GetVaultFiles();
        if (vaultFiles.Length == 0)
        {
            logger.Information("No vaults found in the directory '{Path}'.", NivoraStatics.NivoraApplicationDataPath);
            
            AnsiConsole.WriteLine("No vaults found.");
            return 0;
        }
        logger.Information("Available vaults in '{Path}':", NivoraStatics.NivoraApplicationDataPath);
        var tree = new Tree($"Available vaults in '{NivoraStatics.NivoraApplicationDataPath}':")
        {
            Style = "green"
        }.Guide(TreeGuide.BoldLine);
        
        const int width = 3;
        foreach (var file in vaultFiles.Select((info, i) => new { Info = info, Index = ++i }))
        {
            var indexStr = file.Index.ToString();
            var pad = width - indexStr.Length;
            var padLeft = pad / 2 + indexStr.Length;
            var centered = indexStr.PadLeft(padLeft).PadRight(width);
            tree.AddNodes(new Columns([
                new Markup($"[bold]{centered}[/]"),
                new Markup($"[blue]{file.Info.Name}[/]"),
                new Markup($"[dim](Last modified: {file.Info.LastWriteTime})[/]")
            ]));
        }
        AnsiConsole.Write(tree);

        return 0;
    }
}