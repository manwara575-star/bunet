namespace VideoSecurity.Domain.Entities;

public class SigningKeyVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public SigningKeyPurpose Purpose { get; set; }
    public int Version { get; set; }
    public bool IsActive { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RetiredAt { get; set; }
    public string? Notes { get; set; }
}
