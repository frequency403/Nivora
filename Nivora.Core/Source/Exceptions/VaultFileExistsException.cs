namespace Nivora.Core.Exceptions;

public class VaultFileExistsException : Exception
{
    public VaultFileExistsException(string message, FileInfo info) : base(message)
    {
    }

    public VaultFileExistsException(string message, string filePath) : base(message)
    {
    }

    public static void ThrowIfExists(string filePath)
    {
        if (File.Exists(filePath))
            throw new VaultFileExistsException($"Vault already exists path: {filePath}", filePath);
    }

    public static void ThrowIfExists(FileInfo fileInfo)
    {
        if (fileInfo.Exists)
            throw new VaultFileExistsException($"Vault already exists path: {fileInfo.FullName}", fileInfo);
    }
}