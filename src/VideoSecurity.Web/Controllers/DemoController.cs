using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using System.Text.Json;

namespace VideoSecurity.Web.Controllers;

/// <summary>
/// Public demo page — serves a full-page video player with all security layers active.
/// No login required. Designed for pentest / security review sharing.
/// </summary>
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public sealed class DemoController : Controller
{
    private readonly AppDbContext _db;
    private readonly IPlaybackSessionService _sessions;
    private readonly IBunnyOptionsProvider _bunnyOptions;
    private readonly ILogger<DemoController> _log;

    public DemoController(
        AppDbContext db,
        IPlaybackSessionService sessions,
        IBunnyOptionsProvider bunnyOptions,
        ILogger<DemoController> log)
    {
        _db = db;
        _sessions = sessions;
        _bunnyOptions = bunnyOptions;
        _log = log;
    }

    /// <summary>
    /// GET /demo/{videoId} — public page with embedded video player, no auth required.
    /// </summary>
    [HttpGet("/demo/{videoId:guid}")]
    [EnableRateLimiting("session-create")]
    public async Task<IActionResult> Watch(Guid videoId, CancellationToken ct)
    {
        var opts = await _bunnyOptions.GetAsync(ct);
        if (string.IsNullOrEmpty(opts.EmbedTokenKey))
            return StatusCode(503, "Embed not configured.");

        var video = await _db.Videos.AsNoTracking().FirstOrDefaultAsync(v => v.Id == videoId, ct);
        if (video is null) return NotFound("Video not found.");
        if (video.Status != VideoStatus.Ready)
            return Content("Video is not ready for playback.", "text/plain");

        // Derive a demo user ID from viewer IP for watermark / audit
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = Request.Headers.UserAgent.ToString();
        var demoUserId = "demo:" + EmbedController.ComputeEmbedToken(opts.EmbedTokenKey, videoId, 0)[..12];

        // Ensure a temporary VideoAccessGrant exists
        var now = DateTimeOffset.UtcNow;
        var grantExpiry = now.Add(opts.DefaultSessionTtl).AddMinutes(5);
        var hasGrant = await _db.VideoAccessGrants
            .AsNoTracking()
            .Where(g => g.UserId == demoUserId && g.VideoId == videoId && !g.Revoked)
            .ToListAsync(ct);

        if (!hasGrant.Any(g => g.ExpiresAt == null || g.ExpiresAt > now))
        {
            _db.VideoAccessGrants.Add(new VideoAccessGrant
            {
                UserId = demoUserId,
                VideoId = videoId,
                ExpiresAt = grantExpiry
            });
            await _db.SaveChangesAsync(ct);
        }

        // Create a playback session
        PlaybackSessionResponse session;
        try
        {
            session = await _sessions.CreateAsync(demoUserId, videoId, ip, ua, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to create demo session for video {VideoId}", videoId);
            return StatusCode(500, "Failed to create playback session.");
        }

        ViewBag.Session = session;
        ViewBag.SessionJson = JsonSerializer.Serialize(session, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        ViewBag.VideoTitle = video.Title;
        ViewBag.VideoId = videoId;

        return View();
    }
}
