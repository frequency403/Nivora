namespace Nivora.Core.Database.Models;

public record Secret
{
    public int Id { get; set; } = 0;
    public string Name { get; set; } = string.Empty;
    public string Hash { get; set; } = string.Empty;
    public int Argon2Iterations { get; set; } = 0;
    public int Argon2Memory { get; set; } = 0;
    public int Argon2Parallelism { get; set; } = 0;
    public int Argon2Threads { get; set; } = 0;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; } = null;
    public byte[] Salt { get; set; } = [];
    public byte[] Value { get; set; } = [];
}