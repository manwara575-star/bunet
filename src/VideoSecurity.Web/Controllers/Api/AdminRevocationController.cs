using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Authorize(Policy = "VideoAdminOnly")]
public sealed class AdminRevocationController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IPlaybackSessionService _sessions;
    private readonly IAuditLogService _audit;
    private readonly IBunnyOptionsProvider _options;

    public AdminRevocationController(
        AppDbContext db,
        IPlaybackSessionService sessions,
        IAuditLogService audit,
        IBunnyOptionsProvider options)
    {
        _db = db;
        _sessions = sessions;
        _audit = audit;
        _options = options;
    }

    public sealed record RevokeUserAccessRequest(Guid? VideoId);

    public sealed record RevokeCountResponse(int RevokedCount);

    [HttpPost("api/admin/videos/{id:guid}/revoke-sessions")]
    public async Task<ActionResult<RevokeCountResponse>> RevokeSessionsForVideo(Guid id, CancellationToken ct)
    {
        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
        var opts = await _options.GetAsync(ct);
        var ipHash = AuditHashing.HashIp(opts, HttpContext);
        var uaHash = AuditHashing.HashUa(opts, HttpContext);

        var revokedCount = await _sessions.RevokeAllForVideoAsync(id, "admin-revoke-all", ct);

        await _audit.WriteAsync(
            actor,
            AuditAction.SessionRevoked,
            nameof(Video),
            id.ToString(),
            new { revokedCount, scope = "video" },
            ipHash,
            uaHash,
            ct);

        return Ok(new RevokeCountResponse(revokedCount));
    }

    [HttpPost("api/admin/users/{userId}/revoke-video-access")]
    public async Task<ActionResult<RevokeCountResponse>> RevokeUserAccess(
        [Required] string userId,
        [FromBody] RevokeUserAccessRequest? req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId)) return BadRequest();

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
        var opts = await _options.GetAsync(ct);
        var ipHash = AuditHashing.HashIp(opts, HttpContext);
        var uaHash = AuditHashing.HashUa(opts, HttpContext);
        var scopedVideoId = req?.VideoId;

        var query = _db.VideoAccessGrants.Where(g => g.UserId == userId && !g.Revoked);
        if (scopedVideoId.HasValue)
            query = query.Where(g => g.VideoId == scopedVideoId.Value);

        var grants = await query.ToListAsync(ct);
        foreach (var g in grants)
        {
            // VideoAccessGrant has no RevokedAt column; the boolean Revoked flag is what
            // VideoEntitlementService checks. Treat that as the authoritative revocation marker.
            g.Revoked = true;
        }
        if (grants.Count > 0) await _db.SaveChangesAsync(ct);

        await _audit.WriteAsync(
            actor,
            AuditAction.AccessRevoked,
            nameof(VideoAccessGrant),
            userId,
            new { revokedCount = grants.Count, scopedVideoId },
            ipHash,
            uaHash,
            ct);

        return Ok(new RevokeCountResponse(grants.Count));
    }
}
