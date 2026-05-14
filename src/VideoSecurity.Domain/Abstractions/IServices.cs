using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;

namespace VideoSecurity.Domain.Abstractions;

public interface IVideoEntitlementService
{
    Task<bool> IsAuthorizedAsync(string userId, Guid videoId, CancellationToken ct);
}

public interface IPlaybackSessionService
{
    Task<PlaybackSessionResponse> CreateAsync(string userId, Guid videoId, string ipAddress, string userAgent, CancellationToken ct);
    Task<PlaybackSession?> GetAsync(Guid sessionId, CancellationToken ct);
    Task RecordHeartbeatAsync(HeartbeatRequest request, string userId, CancellationToken ct);
    Task RevokeAsync(Guid sessionId, string reason, CancellationToken ct);
    Task<int> RevokeAllForVideoAsync(Guid videoId, string reason, CancellationToken ct);
}

public interface IAuditLogService
{
    Task WriteAsync(string actorUserId, AuditAction action, string? entityType, string? entityId, object? metadata, string ipHash, string userAgentHash, CancellationToken ct);
}

public interface ISecurityEventService
{
    Task RecordAsync(SecurityEventRequest request, string? userId, string ipAddress, string userAgent, CancellationToken ct);
}

/// <summary>
/// Risk-scoring extensions on <see cref="ISecurityEventService"/>. Kept off the interface
/// so the underlying implementation can stay focused on event recording while higher-level
/// orchestration (heartbeat scoring, auto-revoke) decides how to react.
/// </summary>
public static class SecurityEventServiceExtensions
{
    /// <summary>
    /// Returns an additive risk score increment for the supplied event type. Persisting the
    /// score change is the responsibility of the playback-session pipeline, which already
    /// performs auto-revoke on threshold breach during heartbeats.
    /// </summary>
    public static Task<int> ApplyRiskAsync(this ISecurityEventService _, Guid sessionId, SecurityEventType type, CancellationToken ct)
    {
        var delta = type switch
        {
            SecurityEventType.WatermarkTamper => 15,
            SecurityEventType.RiskAutoRevoke => 0,
            SecurityEventType.ConcurrentSessionLimit => 0,
            SecurityEventType.EntitlementDenied => 0,
            _ => 1
        };
        return Task.FromResult(delta);
    }
}

public interface IVideoSecurityPolicyService
{
    Task<VideoSecurityPolicy> GetForVideoAsync(Guid videoId, CancellationToken ct);
}

public interface ISystemClock
{
    DateTimeOffset UtcNow { get; }
}
