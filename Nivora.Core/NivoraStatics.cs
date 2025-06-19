namespace Nivora.Core;

public static class NivoraStatics
{
    public static string NivoraApplicationDataPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nivora");
    
    public static string NivoraLogsPath = Path.Combine(NivoraApplicationDataPath, "logs");
    public const string DefaultVaultExtension = "niv";
    public const string DefaultVaultExtensionWithDot = ".niv";
    public const string DefaultVaultName = "vault";
}