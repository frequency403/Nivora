using CliFx;
using CliFx.Attributes;
using CliFx.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Nivora.Cli.Commands;
[Command("list-vaults", Description = "Lists all available vaults.")]
public class ListVaultsCommand(ILogger<ListVaultsCommand> logger) : ICommand
{
    public static async Task<FileInfo[]> GetVaultFiles(IConsole console, string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            await console.Output.WriteLineAsync("No vaults found.");
            return [];
        }
        await console.Output.WriteLineAsync("Listing available vaults...");
        return directory.GetFiles("*.niv");
    }
    
    public async ValueTask ExecuteAsync(IConsole console)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nivora");
        
        var vaultFiles = await GetVaultFiles(console, path);
        if (vaultFiles.Length == 0)
        {
            logger.LogInformation("No vaults found in the directory '{Path}'.", path);
            await console.Output.WriteLineAsync("No vaults found.");
            return;
        }
        logger.LogInformation("Available vaults in '{Path}':", path);
        await console.Output.WriteLineAsync($"Available vaults in '{path}':");
        
        const int width = 3;
        foreach (var file in vaultFiles.Select((info, i) => new { Info = info, Index = i }))
        {
            var indexStr = file.Index.ToString();
            var pad = width - indexStr.Length;
            var padLeft = pad / 2 + indexStr.Length;
            var centered = indexStr.PadLeft(padLeft).PadRight(width);
            await console.Output.WriteLineAsync($"- [{centered}] {file.Info.Name} (Last modified: {file.Info.LastWriteTime})");
        }
        
    }
}