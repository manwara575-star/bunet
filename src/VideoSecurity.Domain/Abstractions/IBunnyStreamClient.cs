using VideoSecurity.Domain.Dtos;

namespace VideoSecurity.Domain.Abstractions;

public interface IBunnyStreamClient
{
    Task<BunnyCreateVideoResult> CreateVideoAsync(string title, string? collectionId, CancellationToken ct);
    Task<BunnyVideoInfo> GetVideoAsync(string videoId, CancellationToken ct);
    Task<IReadOnlyList<BunnyVideoInfo>> ListVideosAsync(CancellationToken ct, int page = 1, int perPage = 100);
    Task DeleteVideoAsync(string videoId, CancellationToken ct);
}

public interface IBunnyTusUploadSigner
{
    BunnyTusUploadCredentials CreateCredentials(string videoId, string fileName, TimeSpan ttl);

    /// <summary>
    /// Issues TUS credentials with a dynamically expanded expiration window. When
    /// <paramref name="estimatedFileSizeBytes"/> is supplied, the effective TTL is
    /// <c>max(ttl, 1 hour, ceil(size / assumedUploadBps) + 15 min buffer)</c> so that
    /// large uploads do not expire mid-transfer on slow client links.
    /// </summary>
    BunnyTusUploadCredentials CreateCredentials(string videoId, string fileName, TimeSpan ttl, long? estimatedFileSizeBytes);
}

public interface IBunnyEmbedTokenSigner
{
    /// <summary>
    /// Builds the signed Bunny Embed iframe URL.
    /// Format documented at https://docs.bunny.net/stream/token-authentication
    /// </summary>
    string BuildSignedEmbedUrl(string videoId, DateTimeOffset expires, string? userId, string? sessionId);
}

public interface IBunnyCdnTokenSigner
{
    /// <summary>
    /// Builds an Advanced CDN HMAC-SHA256 token URL for a path (used only when a non-Embed
    /// CDN URL must be exposed — should be rare in v1).
    /// </summary>
    string BuildSignedCdnUrl(string path, DateTimeOffset expires, bool directoryToken = true, string? userIp = null);
}
