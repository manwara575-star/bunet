using System.Text.Json;
using Microsoft.Extensions.Logging;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Services;

public sealed class AuditLogService : IAuditLogService
{
    // AuditLog.MetadataJson column is capped at 4000 chars. Cap a bit lower to leave headroom.
    private const int MetadataJsonMaxChars = 3900;

    private readonly AppDbContext _db;
    private readonly ISystemClock _clock;
    private readonly ILogger<AuditLogService> _log;

    public AuditLogService(AppDbContext db, ISystemClock clock, ILogger<AuditLogService> log)
    {
        _db = db;
        _clock = clock;
        _log = log;
    }

    public async Task WriteAsync(string actorUserId, AuditAction action, string? entityType, string? entityId, object? metadata, string ipHash, string userAgentHash, CancellationToken ct)
    {
        try
        {
            string? json = null;
            if (metadata is not null)
            {
                json = JsonSerializer.Serialize(metadata);
                if (json.Length > MetadataJsonMaxChars)
                    json = json.Substring(0, MetadataJsonMaxChars);
            }

            _db.AuditLogs.Add(new AuditLog
            {
                ActorUserId = string.IsNullOrWhiteSpace(actorUserId) ? "system" : actorUserId,
                Action = action,
                EntityType = entityType,
                EntityId = entityId,
                MetadataJson = json,
                IpHash = ipHash ?? string.Empty,
                UserAgentHash = userAgentHash ?? string.Empty,
                CreatedAt = _clock.UtcNow
            });
            await _db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            // Audit failures must never break the user request.
            _log.LogWarning(ex, "Failed to write audit log entry for action {Action}", action);
        }
    }
}
