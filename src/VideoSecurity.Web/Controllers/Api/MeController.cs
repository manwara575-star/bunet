using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Route("api/me")]
[Authorize]
public sealed class MeController : ControllerBase
{
    private readonly AppDbContext _db;
    public MeController(AppDbContext db) => _db = db;

    /// <summary>List videos the current user has access to (owned or granted).</summary>
    [HttpGet("videos")]
    public async Task<ActionResult> Videos(CancellationToken ct)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var now = DateTimeOffset.UtcNow;

        var activeGrants = await _db.VideoAccessGrants.AsNoTracking()
            .Where(g => !g.Revoked && g.UserId == userId)
            .ToListAsync(ct);
        activeGrants = activeGrants.Where(g => g.ExpiresAt == null || g.ExpiresAt > now).ToList();

        var grantedVideoIds = activeGrants
            .Where(g => g.VideoId != null)
            .Select(g => g.VideoId!.Value)
            .ToList();

        var grantedCourses = activeGrants
            .Where(g => g.CourseId != null)
            .Select(g => g.CourseId!)
            .ToList();

        var items = await _db.Videos.AsNoTracking()
            .Where(v => v.Status != Domain.Entities.VideoStatus.Deleted &&
                        (v.CreatedByUserId == userId
                         || grantedVideoIds.Contains(v.Id)
                         || (v.CourseId != null && grantedCourses.Contains(v.CourseId))))
            .Select(v => new { v.Id, v.Title, v.Description, v.Status, v.DurationSeconds, v.CourseId, v.CreatedAt })
            .ToListAsync(ct);
        items = items.OrderByDescending(v => v.CreatedAt).ToList();

        return Ok(items);
    }

    /// <summary>Get the user's progress for a specific video.</summary>
    [HttpGet("progress/{videoId:guid}")]
    public async Task<ActionResult> Progress(Guid videoId, CancellationToken ct)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var p = await _db.VideoProgress.AsNoTracking()
            .FirstOrDefaultAsync(x => x.UserId == userId && x.VideoId == videoId, ct);
        if (p is null) return Ok(new { videoId, lastPositionSeconds = 0.0, furthestPositionSeconds = 0.0, completed = false });

        return Ok(new { p.VideoId, p.LastPositionSeconds, p.FurthestPositionSeconds, p.Completed, p.UpdatedAt });
    }
}
