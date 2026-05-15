using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Observability;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Services;

public sealed class PlaybackSessionService : IPlaybackSessionService
{
    private readonly AppDbContext _db;
    private readonly IVideoEntitlementService _entitlement;
    private readonly IBunnyEmbedTokenSigner _embedSigner;
    private readonly IBunnyOptionsProvider _options;
    private readonly ISystemClock _clock;
    private readonly IVideoSecurityPolicyService _policies;
    private readonly SecurityMetrics _metrics;

    [ActivatorUtilitiesConstructor]
    public PlaybackSessionService(
        AppDbContext db,
        IVideoEntitlementService entitlement,
        IBunnyEmbedTokenSigner embedSigner,
        IBunnyOptionsProvider options,
        ISystemClock clock,
        IVideoSecurityPolicyService policies,
        SecurityMetrics metrics)
    {
        _db = db;
        _entitlement = entitlement;
        _embedSigner = embedSigner;
        _options = options;
        _clock = clock;
        _policies = policies;
        _metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
    }

    public PlaybackSessionService(
        AppDbContext db,
        IVideoEntitlementService entitlement,
        IBunnyEmbedTokenSigner embedSigner,
        IOptions<BunnyOptions> opts,
        ISystemClock clock,
        IVideoSecurityPolicyService policies,
        SecurityMetrics metrics)
        : this(db, entitlement, embedSigner, new StaticBunnyOptionsProvider(opts.Value), clock, policies, metrics) { }

    public Task<PlaybackSessionResponse> CreateAsync(string userId, Guid videoId, string ipAddress, string userAgent, CancellationToken ct) =>
        CreateAsync(userId, videoId, ipAddress, userAgent, maxSessionTtl: null, ct);

    public Task<PlaybackSessionResponse> CreateAsync(string userId, Guid videoId, string ipAddress, string userAgent, TimeSpan maxSessionTtl, CancellationToken ct) =>
        CreateAsync(userId, videoId, ipAddress, userAgent, (TimeSpan?)maxSessionTtl, ct);

    private async Task<PlaybackSessionResponse> CreateAsync(string userId, Guid videoId, string ipAddress, string userAgent, TimeSpan? maxSessionTtl, CancellationToken ct)
    {
        var opts = await _options.GetAsync(ct);
        if (!await _entitlement.IsAuthorizedAsync(userId, videoId, ct))
        {
            _db.VideoSecurityEvents.Add(new VideoSecurityEvent
            {
                Type = SecurityEventType.EntitlementDenied,
                UserId = userId,
                VideoId = videoId,
                IpHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, ipAddress),
                UserAgentHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, userAgent),
                CreatedAt = _clock.UtcNow
            });
            await _db.SaveChangesAsync(ct);
            _metrics.RecordEntitlementDenied();
            _metrics.RecordSessionDenied("EntitlementDenied");
            throw new UnauthorizedAccessException("User is not entitled to this video.");
        }

        var video = await _db.Videos.AsNoTracking().FirstAsync(v => v.Id == videoId, ct);
        if (video.Status != VideoStatus.Ready)
            throw new InvalidOperationException($"Video is not ready (status={video.Status}).");

        var policy = await _policies.GetForVideoAsync(videoId, ct);

        var now = _clock.UtcNow;
        var ttl = policy.EmbedTtlSeconds > 0
            ? TimeSpan.FromSeconds(policy.EmbedTtlSeconds)
            : opts.DefaultSessionTtl;
        if (maxSessionTtl is { } cap && cap > TimeSpan.Zero && cap < ttl)
            ttl = cap;
        var expires = now.Add(ttl);

        // Enforce concurrent-session limit per (user, video).
        if (policy.MaxConcurrentSessions > 0)
        {
            var candidateSessions = await _db.PlaybackSessions
                .Where(s => s.UserId == userId
                         && s.VideoId == videoId
                         && !s.Revoked)
                .ToListAsync(ct);

            var activeSessions = candidateSessions
                .Where(s => s.ExpiresAt > now)
                .OrderBy(s => s.CreatedAt)
                .ToList();

            // We are about to add one more, so revoke until count < max.
            var idx = 0;
            while (activeSessions.Count - idx >= policy.MaxConcurrentSessions)
            {
                var oldest = activeSessions[idx++];
                oldest.Revoked = true;
                oldest.RevokedAt = now;
                oldest.RevocationReason = "ConcurrentSessionLimit";
                _metrics.RecordConcurrentLimit();
                _metrics.RecordSessionRevoked("ConcurrentSessionLimit");
                _db.VideoSecurityEvents.Add(new VideoSecurityEvent
                {
                    Type = SecurityEventType.ConcurrentSessionLimit,
                    SessionId = oldest.Id,
                    UserId = userId,
                    VideoId = videoId,
                    IpHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, ipAddress),
                    UserAgentHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, userAgent),
                    CreatedAt = now
                });
            }
        }

        var session = new PlaybackSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            VideoId = videoId,
            CreatedAt = now,
            ExpiresAt = expires,
            PlaybackStartedAt = now,
            IpHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, ipAddress),
            UserAgentHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, userAgent),
            WatermarkPayload = string.Empty
        };

        var watermark = BuildWatermark(session, userId, opts);
        session.WatermarkPayload = watermark.DisplayText;
        session.WatermarkPayloadHash = HashUtil.Sha256(watermark.Token);

        _db.PlaybackSessions.Add(session);
        await _db.SaveChangesAsync(ct);
        _metrics.RecordSessionCreated();

        var embedUrl = _embedSigner.BuildSignedEmbedUrl(video.BunnyVideoId, expires, userId, session.Id.ToString("N"));

        return new PlaybackSessionResponse(session.Id, embedUrl, expires, watermark);
    }

    public Task<PlaybackSession?> GetAsync(Guid sessionId, CancellationToken ct) =>
        _db.PlaybackSessions.FirstOrDefaultAsync(s => s.Id == sessionId, ct);

    public async Task RecordHeartbeatAsync(HeartbeatRequest request, string userId, CancellationToken ct)
    {
        var session = await _db.PlaybackSessions.FirstOrDefaultAsync(s => s.Id == request.SessionId, ct);
        if (session is null) throw new KeyNotFoundException("Session not found.");
        if (session.UserId != userId) throw new UnauthorizedAccessException();
        if (session.Revoked) throw new InvalidOperationException("Session revoked.");

        var now = _clock.UtcNow;
        if (now > session.ExpiresAt) throw new InvalidOperationException("Session expired.");

        var policy = await _policies.GetForVideoAsync(session.VideoId, ct);

        if (session.LastHeartbeatAt is { } prev)
        {
            var lag = (now - prev).TotalSeconds;
            if (lag >= 0) _metrics.RecordHeartbeatLag(lag);
        }

        session.LastHeartbeatAt = now;
        session.LastKnownPositionSeconds = request.PositionSeconds;

        // Update or create progress.
        var progress = await _db.VideoProgress.FirstOrDefaultAsync(p => p.UserId == userId && p.VideoId == session.VideoId, ct);
        if (progress is null)
        {
            progress = new VideoProgress { UserId = userId, VideoId = session.VideoId };
            _db.VideoProgress.Add(progress);
        }
        progress.LastPositionSeconds = request.PositionSeconds;
        if (request.PositionSeconds > progress.FurthestPositionSeconds)
            progress.FurthestPositionSeconds = request.PositionSeconds;
        progress.UpdatedAt = now;

        // Risk scoring.
        if (!request.DocumentVisible) session.RiskScore += 1;
        if (!request.DocumentFocused) session.RiskScore += 1;

        if (!request.WatermarkVisible && policy.RequireWatermark)
        {
            session.RiskScore += 15;
            _metrics.RecordWatermarkTamper();
            _db.VideoSecurityEvents.Add(new VideoSecurityEvent
            {
                Type = SecurityEventType.WatermarkTamper,
                SessionId = session.Id,
                UserId = userId,
                VideoId = session.VideoId,
                IpHash = session.IpHash,
                UserAgentHash = session.UserAgentHash,
                CreatedAt = now
            });
        }

        if (!string.IsNullOrWhiteSpace(request.DeviceFingerprint))
        {
            var fpHash = HashUtil.Sha256(request.DeviceFingerprint);
            if (session.DeviceFingerprintHash is null)
            {
                session.DeviceFingerprintHash = fpHash;
            }
            else if (!string.Equals(session.DeviceFingerprintHash, fpHash, StringComparison.Ordinal))
            {
                session.RiskScore += 10;
            }
        }

        if (session.RiskScore >= policy.AutoRevokeRiskThreshold)
        {
            session.Revoked = true;
            session.RevokedAt = now;
            session.RevocationReason = "RiskAutoRevoke";
            _metrics.RecordAutoRevoke("Heartbeat");
            _metrics.RecordSessionRevoked("RiskAutoRevoke");
            _db.VideoSecurityEvents.Add(new VideoSecurityEvent
            {
                Type = SecurityEventType.RiskAutoRevoke,
                SessionId = session.Id,
                UserId = userId,
                VideoId = session.VideoId,
                IpHash = session.IpHash,
                UserAgentHash = session.UserAgentHash,
                MetadataJson = JsonSerializer.Serialize(new { score = session.RiskScore }),
                CreatedAt = now
            });
        }

        await _db.SaveChangesAsync(ct);
        _metrics.RecordHeartbeat();
    }

    public async Task RevokeAsync(Guid sessionId, string reason, CancellationToken ct)
    {
        var session = await _db.PlaybackSessions.FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is null) return;
        session.Revoked = true;
        session.RevokedAt = _clock.UtcNow;
        session.RevocationReason = reason;
        await _db.SaveChangesAsync(ct);
        _metrics.RecordSessionRevoked(reason);
    }

    public async Task<int> RevokeAllForVideoAsync(Guid videoId, string reason, CancellationToken ct)
    {
        var now = _clock.UtcNow;
        // SQLite cannot translate DateTimeOffset comparisons, so filter ExpiresAt client-side.
        var candidates = await _db.PlaybackSessions
            .Where(s => s.VideoId == videoId && !s.Revoked)
            .ToListAsync(ct);
        var active = candidates.Where(s => s.ExpiresAt > now).ToList();
        foreach (var s in active)
        {
            s.Revoked = true;
            s.RevokedAt = now;
            s.RevocationReason = reason;
        }
        if (active.Count > 0)
        {
            await _db.SaveChangesAsync(ct);
            for (var i = 0; i < active.Count; i++) _metrics.RecordSessionRevoked(reason);
        }
        return active.Count;
    }

    private WatermarkPayload BuildWatermark(PlaybackSession session, string userId, BunnyOptions opts)
    {
        var issued = _clock.UtcNow;
        var display = $"{Truncate(userId, 8)} • {session.Id.ToString("N")[..8]} • {issued:yyyy-MM-dd HH:mm}Z";

        var payload = new
        {
            uid = userId,
            sid = session.Id,
            iat = issued.ToUnixTimeSeconds(),
            exp = session.ExpiresAt.ToUnixTimeSeconds()
        };
        var json = JsonSerializer.Serialize(payload);
        var sig = HashUtil.HmacSha256Hex(opts.EmbedTokenKey, json);
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=') + "." + sig;

        return new WatermarkPayload(display, token, issued.ToUnixTimeSeconds(), session.ExpiresAt.ToUnixTimeSeconds());
    }

    private static string Truncate(string s, int len) => s.Length <= len ? s : s[..len];
}

internal static class HashUtil
{
    public static string PseudonymousHash(string? pepper, string fallbackSecret, string input)
    {
        if (string.IsNullOrEmpty(input)) input = "-";
        var secret = !string.IsNullOrWhiteSpace(pepper) ? pepper : fallbackSecret;
        return HmacSha256Hex(secret, input);
    }

    public static string Sha256(string input)
    {
        if (string.IsNullOrEmpty(input)) input = "-";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }

    public static string HmacSha256Hex(string key, string input)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(string.IsNullOrEmpty(key) ? "-" : key));
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }
}
