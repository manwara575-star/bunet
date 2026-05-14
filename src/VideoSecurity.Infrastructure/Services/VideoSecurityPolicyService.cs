using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Services;

public sealed class VideoSecurityPolicyService : IVideoSecurityPolicyService
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(30);

    private readonly AppDbContext _db;
    private readonly IMemoryCache _cache;

    public VideoSecurityPolicyService(AppDbContext db, IMemoryCache cache)
    {
        _db = db;
        _cache = cache;
    }

    public async Task<VideoSecurityPolicy> GetForVideoAsync(Guid videoId, CancellationToken ct)
    {
        var cacheKey = "vsp:video:" + videoId.ToString("N");
        if (_cache.TryGetValue<VideoSecurityPolicy>(cacheKey, out var cached) && cached is not null)
            return cached;

        var video = await _db.Videos.AsNoTracking()
            .Where(v => v.Id == videoId)
            .Select(v => new { v.PolicyId, v.SensitivityTier })
            .FirstOrDefaultAsync(ct);

        VideoSecurityPolicy? policy = null;

        if (video is not null && video.PolicyId is Guid pid)
        {
            policy = await _db.VideoSecurityPolicies.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == pid, ct);
        }

        var tier = video?.SensitivityTier ?? VideoSensitivityTier.Standard;
        if (policy is null)
        {
            policy = await _db.VideoSecurityPolicies.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Tier == tier, ct);
        }

        policy ??= DefaultFor(tier);

        _cache.Set(cacheKey, policy, CacheTtl);
        return policy;
    }

    public static VideoSecurityPolicy DefaultFor(VideoSensitivityTier tier) => tier switch
    {
        VideoSensitivityTier.Critical => new VideoSecurityPolicy
        {
            Tier = VideoSensitivityTier.Critical,
            EmbedTtlSeconds = 300,
            HeartbeatIntervalSeconds = 5,
            MaxConcurrentSessions = 1,
            RequireWatermark = true,
            RevokeOnWatermarkTamper = true,
            AllowIpDrift = false,
            AutoRevokeRiskThreshold = 40
        },
        VideoSensitivityTier.Premium => new VideoSecurityPolicy
        {
            Tier = VideoSensitivityTier.Premium,
            EmbedTtlSeconds = 600,
            HeartbeatIntervalSeconds = 10,
            MaxConcurrentSessions = 1,
            RequireWatermark = true,
            RevokeOnWatermarkTamper = true,
            AllowIpDrift = true,
            AutoRevokeRiskThreshold = 60
        },
        _ => new VideoSecurityPolicy
        {
            Tier = VideoSensitivityTier.Standard,
            EmbedTtlSeconds = 900,
            HeartbeatIntervalSeconds = 15,
            MaxConcurrentSessions = 2,
            RequireWatermark = true,
            RevokeOnWatermarkTamper = true,
            AllowIpDrift = true,
            AutoRevokeRiskThreshold = 80
        }
    };
}
