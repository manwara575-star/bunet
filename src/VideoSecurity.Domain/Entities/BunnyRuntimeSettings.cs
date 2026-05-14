namespace VideoSecurity.Domain.Entities;

public sealed class BunnyRuntimeSettings
{
    public int Id { get; set; } = 1;
    public long LibraryId { get; set; }
    public string ApiKeyProtected { get; set; } = string.Empty;
    public string EmbedTokenKeyProtected { get; set; } = string.Empty;
    public string CdnHostname { get; set; } = string.Empty;
    public string? CdnTokenKeyProtected { get; set; }
    public string ApiBaseUrl { get; set; } = "https://video.bunnycdn.com";
    public string TusEndpoint { get; set; } = "https://video.bunnycdn.com/tusupload";
    public string EmbedBaseUrl { get; set; } = "https://iframe.mediadelivery.net";
    public int DefaultSessionTtlSeconds { get; set; } = 7200;
    public int DefaultUploadTtlSeconds { get; set; } = 14400;
    public bool LockSessionToIp { get; set; }
    public string? PrivacyHashPepperProtected { get; set; }
    public string? WebhookSecretProtected { get; set; }
    public int AssumedUploadBytesPerSecond { get; set; } = 1_500_000;
    public int WebhookEventDedupeWindowSeconds { get; set; } = 86400;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string? UpdatedByUserId { get; set; }
}