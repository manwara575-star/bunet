using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

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
    private readonly IBunnyOptionsProvider _bunnyOptions;
    private readonly PublicPlaybackBootstrapStore _bootstrapStore;
    private readonly ILogger<DemoController> _log;

    public DemoController(
        AppDbContext db,
        IBunnyOptionsProvider bunnyOptions,
        PublicPlaybackBootstrapStore bootstrapStore,
        ILogger<DemoController> log)
    {
        _db = db;
        _bunnyOptions = bunnyOptions;
        _bootstrapStore = bootstrapStore;
        _log = log;
    }

    /// <summary>
    /// GET /demo/{videoId} — public page with embedded video player, no auth required.
    /// </summary>
    [HttpGet("/demo/{videoId:guid}")]
    [EnableRateLimiting("session-create")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> Watch(Guid videoId, CancellationToken ct)
    {
        ApplyNoStoreHeaders();

        var opts = await _bunnyOptions.GetAsync(ct);
        if (string.IsNullOrEmpty(opts.EmbedTokenKey))
            return StatusCode(503, "Embed not configured.");

        var video = await _db.Videos.AsNoTracking().FirstOrDefaultAsync(v => v.Id == videoId, ct);
        if (video is null) return NotFound("Video not found.");
        if (video.Status != VideoStatus.Ready)
            return Content("Video is not ready for playback.", "text/plain");
        if (!video.AllowPublicDemo)
        {
            _log.LogWarning("Rejected public demo playback for non-demo video {VideoId}", videoId);
            return StatusCode(403, "This video is not approved for public demo playback.");
        }

        ViewBag.BootstrapId = _bootstrapStore.Create(videoId, PublicPlaybackKind.Demo);
        ViewBag.VideoTitle = video.Title;
        ViewBag.VideoId = videoId;

        return View();
    }

    private void ApplyNoStoreHeaders()
    {
        Response.Headers.CacheControl = "no-store, private";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
    }
}
