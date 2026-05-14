namespace VideoSecurity.Domain.Entities;

public class AuditLog
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ActorUserId { get; set; } = string.Empty;
    public AuditAction Action { get; set; }
    public string? EntityType { get; set; }
    public string? EntityId { get; set; }
    public string? MetadataJson { get; set; }
    public string IpHash { get; set; } = string.Empty;
    public string UserAgentHash { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public long CreatedAtUtcTicks { get; set; }
}
