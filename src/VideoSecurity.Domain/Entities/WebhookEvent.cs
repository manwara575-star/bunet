namespace VideoSecurity.Domain.Entities;

public class WebhookEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string EventId { get; set; } = string.Empty;
    public string VideoGuid { get; set; } = string.Empty;
    public int? Status { get; set; }
    public string? RawPayload { get; set; }
    public DateTimeOffset ReceivedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ProcessedAt { get; set; }
    public int Attempts { get; set; }
    public string? LastError { get; set; }
}
