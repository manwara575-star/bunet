namespace VideoSecurity.Domain.Entities;

public class VideoSecurityEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public SecurityEventType Type { get; set; }
    public Guid? SessionId { get; set; }
    public string? UserId { get; set; }
    public Guid? VideoId { get; set; }
    public string IpHash { get; set; } = string.Empty;
    public string UserAgentHash { get; set; } = string.Empty;
    public string? MetadataJson { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
