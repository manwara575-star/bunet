namespace VideoSecurity.Domain.Entities;

public class VideoAccessGrant
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public Guid? VideoId { get; set; }
    public string? CourseId { get; set; }
    public DateTimeOffset GrantedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ExpiresAt { get; set; }
    public bool Revoked { get; set; }
}
