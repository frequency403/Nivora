using System.ComponentModel;
using Nivora.Cli.Commands.Arguments.Converters;
using Spectre.Console.Cli;

namespace Nivora.Cli.Commands.Arguments;

public class BaseArguments : CommandSettings
{
    [Description("The name of the vault to use. If not specified, the default vault will be used.")]
    [CommandOption("-v|--vault <vault>")]
    [DefaultValue("vault")]
    public string? VaultName { get; set; }
    
    [Description("The master password for the vault. If not specified, the user will be prompted to enter it.")]
    [CommandOption("-p|--password <Password>")]
    [TypeConverter(typeof(Argon2HashedByteArrayConverter))]
    public byte[] Password { get; set; }
}