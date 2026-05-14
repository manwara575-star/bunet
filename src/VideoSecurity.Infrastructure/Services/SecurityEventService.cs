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

public sealed class SecurityEventService : ISecurityEventService
{
    private readonly AppDbContext _db;
    private readonly ISystemClock _clock;
    private readonly IBunnyOptionsProvider _options;
    private readonly IVideoSecurityPolicyService _policies;
    private readonly SecurityMetrics _metrics;

    [ActivatorUtilitiesConstructor]
    public SecurityEventService(
        AppDbContext db,
        ISystemClock clock,
        IBunnyOptionsProvider options,
        IVideoSecurityPolicyService policies,
        SecurityMetrics metrics)
    {
        _db = db;
        _clock = clock;
        _options = options;
        _policies = policies;
        _metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
    }

    public SecurityEventService(
        AppDbContext db,
        ISystemClock clock,
        IOptions<BunnyOptions> opts,
        IVideoSecurityPolicyService policies,
        SecurityMetrics metrics)
        : this(db, clock, new StaticBunnyOptionsProvider(opts.Value), policies, metrics) { }

    public async Task RecordAsync(SecurityEventRequest request, string? userId, string ipAddress, string userAgent, CancellationToken ct)
    {
        var opts = await _options.GetAsync(ct);
        if (!Enum.TryParse<SecurityEventType>(request.Type, ignoreCase: true, out var type))
            type = SecurityEventType.Other;

        _db.VideoSecurityEvents.Add(new VideoSecurityEvent
        {
            Type = type,
            SessionId = request.SessionId,
            UserId = userId,
            VideoId = request.VideoId,
            IpHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, ipAddress),
            UserAgentHash = HashUtil.PseudonymousHash(opts.PrivacyHashPepper, opts.EmbedTokenKey, userAgent),
            MetadataJson = string.IsNullOrWhiteSpace(request.Metadata) ? null : Truncate(request.Metadata, 4096),
            CreatedAt = _clock.UtcNow
        });
        await _db.SaveChangesAsync(ct);

        _metrics.RecordSecurityEvent(type.ToString());
        if (type == SecurityEventType.WatermarkTamper) _metrics.RecordWatermarkTamper();
        if (type == SecurityEventType.EntitlementDenied) _metrics.RecordEntitlementDenied();

        if (request.SessionId is Guid sid)
        {
            await ApplyRiskAsync(sid, type, userId, ct);
        }
    }

    public Task<int> ApplyRiskAsync(Guid sessionId, SecurityEventType type, CancellationToken ct) =>
        ApplyRiskAsync(sessionId, type, userId: null, ct);

    private async Task<int> ApplyRiskAsync(Guid sessionId, SecurityEventType type, string? userId, CancellationToken ct)
    {
        var session = await _db.PlaybackSessions.FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is null || session.Revoked) return 0;
        if (userId is not null && !string.Equals(session.UserId, userId, StringComparison.Ordinal)) return 0;

        var increment = RiskIncrementFor(type);
        if (increment <= 0) return session.RiskScore;

        session.RiskScore += increment;

        var policy = await _policies.GetForVideoAsync(session.VideoId, ct);
        var now = _clock.UtcNow;

        if (session.RiskScore >= policy.AutoRevokeRiskThreshold)
        {
            session.Revoked = true;
            session.RevokedAt = now;
            session.RevocationReason = "RiskAutoRevoke";
            _metrics.RecordAutoRevoke(type.ToString());
            _metrics.RecordSessionRevoked("RiskAutoRevoke");
            _db.VideoSecurityEvents.Add(new VideoSecurityEvent
            {
                Type = SecurityEventType.RiskAutoRevoke,
                SessionId = session.Id,
                UserId = session.UserId,
                VideoId = session.VideoId,
                IpHash = session.IpHash,
                UserAgentHash = session.UserAgentHash,
                MetadataJson = JsonSerializer.Serialize(new { score = session.RiskScore, trigger = type.ToString() }),
                CreatedAt = now
            });
        }

        await _db.SaveChangesAsync(ct);
        return session.RiskScore;
    }

    private static int RiskIncrementFor(SecurityEventType type) => type switch
    {
        // Low
        SecurityEventType.HeartbeatMissed => 1,
        SecurityEventType.VisibilityHidden => 1,
        SecurityEventType.FocusLost => 1,
        // Medium
        SecurityEventType.DevToolsOpen => 10,
        SecurityEventType.OriginMismatch => 10,
        SecurityEventType.RawUrlProbe => 10,
        SecurityEventType.EntitlementDenied => 10,
        // High
        SecurityEventType.SuspectedRecording => 25,
        SecurityEventType.ScreenCaptureAttempt => 25,
        SecurityEventType.DownloadAttempt => 25,
        SecurityEventType.TokenReplay => 25,
        SecurityEventType.WatermarkTamper => 25,
        SecurityEventType.ConcurrentSessionLimit => 25,
        _ => 0
    };

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
