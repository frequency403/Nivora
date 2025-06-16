namespace Nivora.Core.Models;

public record Salt
{
    public readonly byte[] Bytes;

    private Salt(byte size = 0x0C)
    {
        Bytes = new byte[size];
        Random.Shared.NextBytes(Bytes);
    }

    private Salt(byte[] bytes)
    {
        Bytes = bytes;
    }

    public static Salt Generate()
    {
        return new Salt();
    }

    public static Salt Generate(byte size)
    {
        return new Salt(size);
    }

    public static Salt FromBytes(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0)
            throw new ArgumentException("Salt bytes cannot be null or empty.", nameof(bytes));

        return new Salt(bytes);
    }
}