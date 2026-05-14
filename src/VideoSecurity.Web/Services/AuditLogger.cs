using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Services;

public sealed class AuditLogger
{
    private readonly AppDbContext _db;
    private readonly IBunnyOptionsProvider _options;

    public AuditLogger(AppDbContext db, IBunnyOptionsProvider options)
    {
        _db = db;
        _options = options;
    }

    public async Task RecordAsync(ClaimsPrincipal user, HttpContext http, AuditAction action, string? entityType, string? entityId, object? metadata, CancellationToken ct)
    {
        var actor = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
        var ip = http.Connection.RemoteIpAddress?.ToString() ?? $"unknown:{http.TraceIdentifier}";
        var ua = http.Request.Headers.UserAgent.ToString();
        var opts = await _options.GetAsync(ct);
        _db.AuditLogs.Add(new AuditLog
        {
            ActorUserId = actor,
            Action = action,
            EntityType = entityType,
            EntityId = entityId,
            MetadataJson = metadata is null ? null : JsonSerializer.Serialize(metadata),
            IpHash = PseudonymousHash(opts, ip),
            UserAgentHash = PseudonymousHash(opts, ua),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await _db.SaveChangesAsync(ct);
        VideoSecurityMetrics.AdminActions.Add(1, new KeyValuePair<string, object?>("action", action.ToString()));
    }

    private static string PseudonymousHash(BunnyOptions opts, string input)
    {
        if (string.IsNullOrEmpty(input)) input = "-";
        var secret = !string.IsNullOrWhiteSpace(opts.PrivacyHashPepper) ? opts.PrivacyHashPepper : opts.EmbedTokenKey;
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(string.IsNullOrEmpty(secret) ? "-" : secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }
}
