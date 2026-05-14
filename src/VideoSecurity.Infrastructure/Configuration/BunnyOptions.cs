using System.ComponentModel.DataAnnotations;

namespace VideoSecurity.Infrastructure.Configuration;

public sealed class BunnyOptions
{
    public const string SectionName = "Bunny";

    /// <summary>Bunny Stream library numeric ID.</summary>
    [Range(1, long.MaxValue)]
    public long LibraryId { get; set; }

    /// <summary>Stream library API key (NEVER log this). Used for create-video / status / delete.</summary>
    [Required]
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>
    /// Embed View "Token Authentication Key" from the library's security settings.
    /// Used to sign iframe URLs (https://docs.bunny.net/stream/token-authentication).
    /// </summary>
    [Required]
    public string EmbedTokenKey { get; set; } = string.Empty;

    /// <summary>Pull Zone hostname for the library, e.g. "vz-xxxxxx.b-cdn.net".</summary>
    [Required]
    public string CdnHostname { get; set; } = string.Empty;

    /// <summary>
    /// Optional: CDN Pull Zone Token Authentication Key used for Advanced URL token signing
    /// (https://docs.bunny.net/cdn/security/token-authentication/advanced).
    /// </summary>
    public string? CdnTokenKey { get; set; }

    /// <summary>Bunny Stream API base URL. Defaults to https://video.bunnycdn.com.</summary>
    public string ApiBaseUrl { get; set; } = "https://video.bunnycdn.com";

    /// <summary>Bunny Stream TUS upload endpoint.</summary>
    public string TusEndpoint { get; set; } = "https://video.bunnycdn.com/tusupload";

    /// <summary>Bunny embed iframe base URL.</summary>
    public string EmbedBaseUrl { get; set; } = "https://iframe.mediadelivery.net";

    /// <summary>Default playback-session TTL.</summary>
    public TimeSpan DefaultSessionTtl { get; set; } = TimeSpan.FromHours(2);

    /// <summary>Default upload credential TTL.</summary>
    public TimeSpan DefaultUploadTtl { get; set; } = TimeSpan.FromHours(4);

    /// <summary>If true, enforce IP locking on tokens (paranoid). Default false (balanced).</summary>
    public bool LockSessionToIp { get; set; } = false;

    /// <summary>
    /// Optional pepper used to HMAC IP/user-agent audit values. If omitted, EmbedTokenKey is used.
    /// Set a dedicated secret in production so low-entropy IPv4 addresses are not brute-forceable.
    /// </summary>
    public string? PrivacyHashPepper { get; set; }

    /// <summary>Shared secret used to verify webhook authenticity (header X-Bunny-Webhook-Secret).</summary>
    public string? WebhookSecret { get; set; }

    /// <summary>
    /// Conservative assumed upload throughput in bytes/second used to size the TUS expiration window
    /// when an estimated file size hint is supplied. Default 1.5 MB/s ~= 12 Mbps.
    /// </summary>
    [Range(1, int.MaxValue)]
    public int AssumedUploadBytesPerSecond { get; set; } = 1_500_000;

    /// <summary>
    /// Retention window for de-duplicating Bunny webhook events by EventId. Older WebhookEvent rows
    /// may be cleaned up by a maintenance job (not provided here).
    /// </summary>
    public TimeSpan WebhookEventDedupeWindow { get; set; } = TimeSpan.FromHours(24);
}
