using System.Globalization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers;

public sealed class MetricsController : ControllerBase
{
    private readonly AppDbContext _db;
    public MetricsController(AppDbContext db) => _db = db;

    [HttpGet("/metrics/app")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var nowTicks = DateTimeOffset.UtcNow.UtcDateTime.Ticks;
        var activeSessions = await _db.PlaybackSessions.CountAsync(s => !s.Revoked && s.ExpiresAtUtcTicks > nowTicks, ct);
        var revokedSessions = await _db.PlaybackSessions.CountAsync(s => s.Revoked, ct);
        var readyVideos = await _db.Videos.CountAsync(v => v.Status == Domain.Entities.VideoStatus.Ready, ct);
        var securityEvents = await _db.VideoSecurityEvents.CountAsync(ct);
        var webhookReceipts = await _db.BunnyWebhookReceipts.CountAsync(ct);

        var lines = new[]
        {
            "# HELP videosecurity_active_playback_sessions Active non-revoked playback sessions.",
            "# TYPE videosecurity_active_playback_sessions gauge",
            $"videosecurity_active_playback_sessions {activeSessions.ToString(CultureInfo.InvariantCulture)}",
            "# HELP videosecurity_revoked_playback_sessions Revoked playback sessions.",
            "# TYPE videosecurity_revoked_playback_sessions gauge",
            $"videosecurity_revoked_playback_sessions {revokedSessions.ToString(CultureInfo.InvariantCulture)}",
            "# HELP videosecurity_ready_videos Videos currently marked Ready.",
            "# TYPE videosecurity_ready_videos gauge",
            $"videosecurity_ready_videos {readyVideos.ToString(CultureInfo.InvariantCulture)}",
            "# HELP videosecurity_security_events_total Persisted security events.",
            "# TYPE videosecurity_security_events_total counter",
            $"videosecurity_security_events_total {securityEvents.ToString(CultureInfo.InvariantCulture)}",
            "# HELP videosecurity_webhook_receipts_total Persisted Bunny webhook receipts.",
            "# TYPE videosecurity_webhook_receipts_total counter",
            $"videosecurity_webhook_receipts_total {webhookReceipts.ToString(CultureInfo.InvariantCulture)}"
        };

        return Content(string.Join('\n', lines) + "\n", "text/plain; version=0.0.4; charset=utf-8");
    }
}
