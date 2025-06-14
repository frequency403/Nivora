using System.Diagnostics.CodeAnalysis;

namespace Nivora.Core.Models;

public record VaultVersion
{
    public static VaultVersion Current { get; } = new(1, 0, 0);
    
    public int Major { get; set; } = 0;
    public int Minor { get; set; } = 0;
    public int Patch { get; set; } = 0;
    
    public VaultVersion(int major, int minor, int patch)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
    }

    public VaultVersion(int major, int minor)
    {
        Major = major;
        Minor = minor;
    }
    
    public VaultVersion(int major)
    {
        Major = major;
    }
    
    private VaultVersion() { }
    
    public static VaultVersion FromBytes(byte[] bytes)
    {
        if (bytes == null || bytes.Length < 3)
            throw new ArgumentException("Vault version bytes must contain at least 3 elements.", nameof(bytes));
        
        return new VaultVersion(bytes[0], bytes[1], bytes[2]);
    }
    
    public static bool TryFromBytes(byte[]? bytes, [NotNullWhen(true)] out VaultVersion? version)
    {
        version = null;
        if (bytes == null || bytes.Length < 3)
            return false;

        try
        {
            version = FromBytes(bytes);
            return true;
        }
        catch
        {
            return false;
        }
    }
    
    public byte[] ToBytes()
    {
        return [(byte)Major, (byte)Minor, (byte)Patch];
    }

    public override string ToString() => $"{nameof(VaultVersion)}: {Major}.{Minor}.{Patch}";
}