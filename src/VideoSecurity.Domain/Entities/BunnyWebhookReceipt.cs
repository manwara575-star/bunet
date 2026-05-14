namespace VideoSecurity.Domain.Entities;

public sealed class BunnyWebhookReceipt
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string BodyHash { get; set; } = string.Empty;
    public string SignatureHash { get; set; } = string.Empty;
    public string? VideoGuid { get; set; }
    public int? Status { get; set; }
    public DateTimeOffset ReceivedAt { get; set; } = DateTimeOffset.UtcNow;
}
