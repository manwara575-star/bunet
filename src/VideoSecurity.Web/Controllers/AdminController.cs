using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Controllers;

[Authorize(Policy = "AdminOnly")]
public sealed class AdminController : Controller
{
    private readonly AppDbContext _db;
    private readonly IAuditLogService _audit;
    private readonly IBunnyOptionsProvider _options;
    private readonly IBunnyStreamClient _bunny;
    private readonly ILogger<AdminController> _log;

    public AdminController(AppDbContext db, IAuditLogService audit, IBunnyOptionsProvider options,
        IBunnyStreamClient bunny, ILogger<AdminController> log)
    {
        _db = db;
        _audit = audit;
        _options = options;
        _bunny = bunny;
        _log = log;
    }

    [HttpGet("/admin")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var videos = await _db.Videos.AsNoTracking()
            .Where(v => v.Status != VideoStatus.Deleted)
            .ToListAsync(ct);
        videos = videos.OrderByDescending(v => v.CreatedAt).Take(100).ToList();
        return View(videos);
    }

    [HttpGet("/admin/upload")]
    public IActionResult Upload() => View();

    [HttpPost("/admin/grant")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Grant(string userId, Guid videoId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId)) return BadRequest();
        var exists = await _db.VideoAccessGrants.AnyAsync(g => g.UserId == userId && g.VideoId == videoId && !g.Revoked, ct);
        if (!exists)
        {
            _db.VideoAccessGrants.Add(new VideoAccessGrant { UserId = userId, VideoId = videoId });
            await _db.SaveChangesAsync(ct);
            var opts = await _options.GetAsync(ct);
            await _audit.WriteAsync(
                User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "system",
                AuditAction.AccessGranted,
                nameof(Video),
                videoId.ToString(),
                new { userId },
                AuditHashing.HashIp(opts, HttpContext),
                AuditHashing.HashUa(opts, HttpContext),
                ct);
        }
        return RedirectToAction(nameof(Index));
    }

    [HttpGet("/admin/sync/{id:guid}")]
    public async Task<IActionResult> SyncOne(Guid id, CancellationToken ct)
    {
        var v = await _db.Videos.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (v is null) return NotFound();

        try
        {
            var info = await _bunny.GetVideoAsync(v.BunnyVideoId, ct);
            var newStatus = MapBunnyStatus(info.Status);
            v.Status = newStatus;
            v.DurationSeconds = info.Length;
            v.UpdatedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(ct);
            TempData["SyncResult"] = $"✅ \"{v.Title}\" synced → {newStatus}";
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Sync failed for video {VideoId}", id);
            TempData["SyncResult"] = $"❌ Sync failed for \"{v.Title}\": {ex.Message}";
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpGet("/admin/sync-all")]
    public async Task<IActionResult> SyncAll(CancellationToken ct)
    {
        int imported = 0, updated = 0, failed = 0;
        try
        {
            var bunnyVideos = await _bunny.ListVideosAsync(ct);
            var existingByBunnyId = await _db.Videos
                .Where(v => v.Status != VideoStatus.Deleted)
                .ToDictionaryAsync(v => v.BunnyVideoId, ct);
            var opts = await _options.GetAsync(ct);

            foreach (var bv in bunnyVideos)
            {
                try
                {
                    if (existingByBunnyId.TryGetValue(bv.Guid, out var local))
                    {
                        var newStatus = MapBunnyStatus(bv.Status);
                        if (newStatus != local.Status || Math.Abs(bv.Length - local.DurationSeconds) > 0.01)
                        {
                            local.Status = newStatus;
                            local.DurationSeconds = bv.Length;
                            local.Title = string.IsNullOrWhiteSpace(local.Title) ? bv.Title : local.Title;
                            local.UpdatedAt = DateTimeOffset.UtcNow;
                            updated++;
                        }
                    }
                    else
                    {
                        _db.Videos.Add(new Video
                        {
                            Title = bv.Title,
                            BunnyLibraryId = bv.LibraryId,
                            BunnyVideoId = bv.Guid,
                            BunnyCollectionId = bv.CollectionId,
                            Status = MapBunnyStatus(bv.Status),
                            DurationSeconds = bv.Length,
                            CreatedAt = bv.DateUploaded,
                            UpdatedAt = DateTimeOffset.UtcNow,
                            CreatedByUserId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "import"
                        });
                        imported++;
                    }
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Sync failed for Bunny video {BunnyGuid}", bv.Guid);
                    failed++;
                }
            }

            await _db.SaveChangesAsync(ct);
            TempData["SyncResult"] = $"✅ Imported {imported}, updated {updated} video(s) from Bunny" + (failed > 0 ? $", {failed} failed" : "");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "SyncAll failed");
            TempData["SyncResult"] = $"❌ Sync failed: {ex.Message}";
        }

        return RedirectToAction(nameof(Index));
    }

    private static VideoStatus MapBunnyStatus(int code) => code switch
    {
        0 => VideoStatus.Created,
        1 or 2 or 3 => VideoStatus.Processing,
        4 => VideoStatus.Ready,
        5 or 6 => VideoStatus.Failed,
        _ => VideoStatus.Processing
    };
}
