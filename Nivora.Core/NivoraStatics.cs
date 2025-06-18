namespace Nivora.Core;

public static class NivoraStatics
{
    public static string NivoraApplicationDataPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nivora");
    
    public static string NivoraLogsPath = Path.Combine(NivoraApplicationDataPath, "logs");
    
}