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
        var videos = await _db.Videos
            .Where(v => v.Status != VideoStatus.Deleted && v.Status != VideoStatus.Ready)
            .ToListAsync(ct);

        int synced = 0, failed = 0;
        foreach (var v in videos)
        {
            try
            {
                var info = await _bunny.GetVideoAsync(v.BunnyVideoId, ct);
                var newStatus = MapBunnyStatus(info.Status);
                if (newStatus != v.Status || Math.Abs(info.Length - v.DurationSeconds) > 0.01)
                {
                    v.Status = newStatus;
                    v.DurationSeconds = info.Length;
                    v.UpdatedAt = DateTimeOffset.UtcNow;
                    synced++;
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Sync failed for video {VideoId}", v.Id);
                failed++;
            }
        }

        await _db.SaveChangesAsync(ct);
        TempData["SyncResult"] = $"✅ Synced {synced} video(s) from Bunny" + (failed > 0 ? $", {failed} failed" : "");
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
