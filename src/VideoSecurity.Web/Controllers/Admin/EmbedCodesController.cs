using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Controllers;

namespace VideoSecurity.Web.Controllers.Admin;

/// <summary>
/// Admin page to generate secure embed codes for videos.
/// </summary>
[Authorize(Policy = "VideoAdminOnly")]
public sealed class EmbedCodesController : Controller
{
    private readonly AppDbContext _db;
    private readonly IBunnyOptionsProvider _options;
    private readonly IConfiguration _config;

    public EmbedCodesController(AppDbContext db, IBunnyOptionsProvider options, IConfiguration config)
    {
        _db = db;
        _options = options;
        _config = config;
    }

    [HttpGet("/admin/embed-codes")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var videos = (await _db.Videos
            .AsNoTracking()
            .Where(v => v.Status == VideoStatus.Ready)
            .ToListAsync(ct))
            .OrderByDescending(v => v.CreatedAt)
            .ToList();

        ViewBag.Videos = videos;
        return View();
    }

    [HttpGet("/admin/embed-codes/{videoId:guid}")]
    public async Task<IActionResult> Generate(Guid videoId, CancellationToken ct)
    {
        var video = await _db.Videos.AsNoTracking().FirstOrDefaultAsync(v => v.Id == videoId, ct);
        if (video is null) return NotFound();

        var opts = await _options.GetAsync(ct);
        if (string.IsNullOrEmpty(opts.EmbedTokenKey))
        {
            TempData["Error"] = "Bunny EmbedTokenKey is not configured. Go to Bunny Settings first.";
            return RedirectToAction(nameof(Index));
        }

        // Generate a short-lived bearer embed token. Permanent public embeds are not allowed.
        var expires15m = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds();
        var token15m = EmbedController.ComputeEmbedToken(opts.EmbedTokenKey, videoId, expires15m);

        // Determine public base URL
        var publicBaseUrl = _config["Embed:PublicBaseUrl"];
        if (string.IsNullOrWhiteSpace(publicBaseUrl))
            publicBaseUrl = $"{Request.Scheme}://{Request.Host}";
        publicBaseUrl = publicBaseUrl.TrimEnd('/');

        var timedUrl = $"{publicBaseUrl}/embed/{videoId}?token={token15m}&expires={expires15m}";

        ViewBag.Video = video;
        ViewBag.TimedUrl = timedUrl;
        ViewBag.PublicBaseUrl = publicBaseUrl;
        ViewBag.TimedHtml = BuildIframeHtml(timedUrl);
        ViewBag.ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expires15m);

        return View();
    }

    private static string BuildIframeHtml(string url) =>
        $"<iframe src=\"{url}\" width=\"1280\" height=\"720\" frameborder=\"0\" " +
        "allow=\"encrypted-media; autoplay\" referrerpolicy=\"no-referrer\" " +
        "style=\"max-width:100%; aspect-ratio:16/9;\"></iframe>";
}
