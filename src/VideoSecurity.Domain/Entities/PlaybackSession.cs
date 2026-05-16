namespace VideoSecurity.Domain.Entities;

public class PlaybackSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public Guid VideoId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public long CreatedAtUtcTicks { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public long ExpiresAtUtcTicks { get; set; }
    public DateTimeOffset? LastHeartbeatAt { get; set; }
    public long LastHeartbeatAtUtcTicks { get; set; }
    public string IpHash { get; set; } = string.Empty;
    public string UserAgentHash { get; set; } = string.Empty;
    public int RiskScore { get; set; }
    public bool Revoked { get; set; }
    public string? RevocationReason { get; set; }
    public string WatermarkPayload { get; set; } = string.Empty;

    public string? DeviceFingerprintHash { get; set; }
    public string? WatermarkPayloadHash { get; set; }
    public string? HeartbeatTokenHash { get; set; }
    public DateTimeOffset? PlaybackStartedAt { get; set; }
    public double LastKnownPositionSeconds { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
