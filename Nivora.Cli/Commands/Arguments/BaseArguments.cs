using Spectre.Console.Cli;

namespace Nivora.Cli.Commands.Arguments;

public class BaseArguments : CommandSettings
{
    [CommandOption("-v|--vault <vault>")]
    public string? VaultName { get; set; }
    
    [CommandArgument(0, "[Password]")]
    public string Password { get; set; }
}