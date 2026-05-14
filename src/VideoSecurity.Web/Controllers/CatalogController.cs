using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers;

[Authorize]
public sealed class CatalogController : Controller
{
    private readonly AppDbContext _db;
    public CatalogController(AppDbContext db) => _db = db;

    [HttpGet("/catalog")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
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
            .Where(v => v.Status == VideoStatus.Ready &&
                        (v.CreatedByUserId == userId
                         || grantedVideoIds.Contains(v.Id)
                         || (v.CourseId != null && grantedCourses.Contains(v.CourseId))))
            .ToListAsync(ct);
        items = items.OrderByDescending(v => v.CreatedAt).ToList();

        return View(items);
    }
}
