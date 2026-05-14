using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Route("api/admin/sessions")]
[Authorize(Policy = "AdminOnly")]
public sealed class AdminSessionsController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IPlaybackSessionService _sessions;
    private readonly AuditLogger _audit;
    public AdminSessionsController(AppDbContext db, IPlaybackSessionService sessions, AuditLogger audit)
    {
        _db = db; _sessions = sessions; _audit = audit;
    }

    [HttpGet]
    public async Task<ActionResult> List([FromQuery] string? userId, [FromQuery] Guid? videoId, [FromQuery] int take = 100, CancellationToken ct = default)
    {
        take = Math.Clamp(take, 1, 500);
        var q = _db.PlaybackSessions.AsNoTracking().AsQueryable();
        if (!string.IsNullOrEmpty(userId)) q = q.Where(s => s.UserId == userId);
        if (videoId.HasValue) q = q.Where(s => s.VideoId == videoId.Value);

        var items = await q
            .Select(s => new { s.Id, s.UserId, s.VideoId, s.CreatedAt, s.ExpiresAt, s.LastHeartbeatAt, s.RiskScore, s.Revoked, s.RevocationReason })
            .ToListAsync(ct);
        items = items.OrderByDescending(s => s.CreatedAt).Take(take).ToList();
        return Ok(items);
    }

    [HttpPost("{sessionId:guid}/revoke")]
    public async Task<ActionResult> Revoke(Guid sessionId, [FromQuery] string reason = "admin-revoke", CancellationToken ct = default)
    {
        await _sessions.RevokeAsync(sessionId, reason, ct);
        await _audit.RecordAsync(User, HttpContext, AuditAction.SessionRevoked, "PlaybackSession", sessionId.ToString(), new { reason }, ct);
        return NoContent();
    }
}
