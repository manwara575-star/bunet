namespace VideoSecurity.Domain.Entities;

public class VideoProgress
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public Guid VideoId { get; set; }
    public double LastPositionSeconds { get; set; }
    public double FurthestPositionSeconds { get; set; }
    public bool Completed { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
