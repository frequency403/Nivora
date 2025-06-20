using System.ComponentModel;
using Nivora.Cli.Commands.Arguments.Converters;
using Nivora.Core.Enums;
using Spectre.Console.Cli;

namespace Nivora.Cli.Commands.Arguments;

public class UseArguments : BaseArguments
{
    [CommandOption("--secretName <name>")]
    [Description("The name of the secret to use. If not specified, the user will be prompted to enter it.")]
    public string? SecretName { get; set; }
    
    [CommandOption("--secretValue <value>")]
    [Description("The value of the secret to use. If not specified, the user will be prompted to enter it.")]
    public string? SecretValue { get; set; }
    
    [CommandOption("-o|--operation <operation>")]
    [Description("The operation to perform on the vault. If not specified, the user will be prompted to select an operation.")]
    [TypeConverter(typeof(VaultOperationConverter))]
    public VaultOperation? Operation { get; set; }
}