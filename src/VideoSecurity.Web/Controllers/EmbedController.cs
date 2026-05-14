using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers;

/// <summary>
/// Public embed endpoint — serves the protected player inside an iframe on external sites.
/// Authorization is via a signed embed URL token, NOT ASP.NET Identity.
/// All playback security features (watermark, heartbeat, risk scoring) remain active.
/// </summary>
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public sealed class EmbedController : Controller
{
    private readonly AppDbContext _db;
    private readonly IPlaybackSessionService _sessions;
    private readonly IBunnyOptionsProvider _bunnyOptions;
    private readonly ILogger<EmbedController> _log;

    public EmbedController(
        AppDbContext db,
        IPlaybackSessionService sessions,
        IBunnyOptionsProvider bunnyOptions,
        ILogger<EmbedController> log)
    {
        _db = db;
        _sessions = sessions;
        _bunnyOptions = bunnyOptions;
        _log = log;
    }

    /// <summary>
    /// GET /embed/{videoId}?token=xxx&amp;expires=yyy
    /// Validates the embed token, creates a playback session, and renders the player.
    /// </summary>
    [HttpGet("/embed/{videoId:guid}")]
    [EnableRateLimiting("session-create")]
    public async Task<IActionResult> Watch(Guid videoId, string? token, long expires, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token))
            return BadRequest("Missing token parameter.");

        // 1. Validate embed token
        var opts = await _bunnyOptions.GetAsync(ct);
        if (string.IsNullOrEmpty(opts.EmbedTokenKey))
            return StatusCode(503, "Embed not configured.");

        var expected = ComputeEmbedToken(opts.EmbedTokenKey, videoId, expires);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(token),
                Encoding.UTF8.GetBytes(expected)))
        {
            _log.LogWarning("Invalid embed token for video {VideoId}", videoId);
            return StatusCode(403, "Invalid embed token.");
        }

        // 2. Check expiry (0 = permanent embed link)
        if (expires > 0)
        {
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expires);
            if (DateTimeOffset.UtcNow > expiresAt)
                return StatusCode(410, "Embed link has expired.");
        }

        // 3. Check video exists and is ready
        var video = await _db.Videos.AsNoTracking().FirstOrDefaultAsync(v => v.Id == videoId, ct);
        if (video is null) return NotFound("Video not found.");
        if (video.Status != VideoStatus.Ready) return Content("Video is not ready for playback.", "text/plain");

        // 4. Derive embed user ID from viewer IP
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = Request.Headers.UserAgent.ToString();
        var embedUserId = "embed:" + Sha256Hex(ip)[..16];

        // 5. Ensure a temporary VideoAccessGrant exists for the embed viewer
        var now = DateTimeOffset.UtcNow;
        var grantExpiry = now.Add(opts.DefaultSessionTtl).AddMinutes(5);
        var hasGrant = await _db.VideoAccessGrants
            .AsNoTracking()
            .Where(g => g.UserId == embedUserId && g.VideoId == videoId && !g.Revoked)
            .ToListAsync(ct);

        if (!hasGrant.Any(g => g.ExpiresAt == null || g.ExpiresAt > now))
        {
            _db.VideoAccessGrants.Add(new VideoAccessGrant
            {
                UserId = embedUserId,
                VideoId = videoId,
                ExpiresAt = grantExpiry
            });
            await _db.SaveChangesAsync(ct);
        }

        // 6. Create a playback session via the standard service
        PlaybackSessionResponse session;
        try
        {
            session = await _sessions.CreateAsync(embedUserId, videoId, ip, ua, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to create embed session for video {VideoId}", videoId);
            return StatusCode(500, "Failed to create playback session.");
        }

        // 7. Render the standalone embed player
        ViewBag.Session = session;
        ViewBag.SessionJson = JsonSerializer.Serialize(session, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        ViewBag.VideoTitle = video.Title;
        ViewBag.VideoId = videoId;
        return View();
    }

    /// <summary>
    /// POST /embed/heartbeat — records heartbeat for embed sessions.
    /// Uses the session's stored userId for authorization (no ASP.NET Identity needed).
    /// </summary>
    [HttpPost("/embed/heartbeat")]
    [EnableRateLimiting("heartbeat")]
    [RequestSizeLimit(4 * 1024)]
    public async Task<IActionResult> Heartbeat([FromBody] HeartbeatRequest req, CancellationToken ct)
    {
        if (req is null) return BadRequest();

        var session = await _db.PlaybackSessions
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == req.SessionId, ct);

        if (session is null) return NotFound();

        // Only allow heartbeats for embed sessions
        if (!session.UserId.StartsWith("embed:", StringComparison.Ordinal))
            return Forbid();

        try
        {
            await _sessions.RecordHeartbeatAsync(req, session.UserId, ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (UnauthorizedAccessException) { return Forbid(); }
        catch (InvalidOperationException ex) { return Conflict(new { error = ex.Message }); }
    }

    /// <summary>
    /// Computes the embed token: SHA256(EmbedTokenKey + "|embed|" + videoId + "|" + expires).
    /// </summary>
    internal static string ComputeEmbedToken(string embedTokenKey, Guid videoId, long expires)
    {
        var raw = embedTokenKey + "|embed|" + videoId + "|" + expires;
        return Sha256Hex(raw);
    }

    private static string Sha256Hex(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
}
