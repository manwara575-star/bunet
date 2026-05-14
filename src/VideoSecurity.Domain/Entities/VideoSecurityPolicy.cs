namespace VideoSecurity.Domain.Entities;

public class VideoSecurityPolicy
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public VideoSensitivityTier Tier { get; set; }
    public int EmbedTtlSeconds { get; set; } = 900;
    public int HeartbeatIntervalSeconds { get; set; } = 15;
    public int MaxConcurrentSessions { get; set; } = 2;
    public bool RequireWatermark { get; set; } = true;
    public bool RevokeOnWatermarkTamper { get; set; } = true;
    public bool AllowIpDrift { get; set; } = true;
    public int AutoRevokeRiskThreshold { get; set; } = 80;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
