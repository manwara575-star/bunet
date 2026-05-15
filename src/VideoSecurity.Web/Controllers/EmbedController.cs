using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

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
    private readonly PublicPlaybackBootstrapStore _bootstrapStore;
    private readonly ILogger<EmbedController> _log;

    public EmbedController(
        AppDbContext db,
        IPlaybackSessionService sessions,
        IBunnyOptionsProvider bunnyOptions,
        PublicPlaybackBootstrapStore bootstrapStore,
        ILogger<EmbedController> log)
    {
        _db = db;
        _sessions = sessions;
        _bunnyOptions = bunnyOptions;
        _bootstrapStore = bootstrapStore;
        _log = log;
    }

    /// <summary>
    /// GET /embed/{videoId}?token=xxx&amp;expires=yyy
    /// Validates the embed token, creates a playback session, and renders the player.
    /// </summary>
    [HttpGet("/embed/{videoId:guid}")]
    [EnableRateLimiting("session-create")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> Watch(Guid videoId, string? token, long expires, CancellationToken ct)
    {
        ApplyNoStoreHeaders();

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

        // 2. Check expiry. Permanent public embed links are not allowed.
        if (expires <= 0)
            return BadRequest("Permanent embed links are not allowed.");

        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expires);
        if (DateTimeOffset.UtcNow > expiresAt)
            return StatusCode(410, "Embed link has expired.");

        // 3. Check video exists and is ready
        var video = await _db.Videos.AsNoTracking().FirstOrDefaultAsync(v => v.Id == videoId, ct);
        if (video is null) return NotFound("Video not found.");
        if (video.Status != VideoStatus.Ready) return Content("Video is not ready for playback.", "text/plain");

        ViewBag.BootstrapId = _bootstrapStore.Create(videoId, PublicPlaybackKind.Embed);
        ViewBag.VideoTitle = video.Title;
        ViewBag.VideoId = videoId;
        return View();
    }

    [HttpPost("/public-playback/bootstrap/{bootstrapId}")]
    [EnableRateLimiting("session-create")]
    [RequestSizeLimit(1024)]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<ActionResult<PlaybackSessionResponse>> Bootstrap(string bootstrapId, CancellationToken ct)
    {
        ApplyNoStoreHeaders();

        if (!_bootstrapStore.TryConsume(bootstrapId, out var bootstrap))
            return StatusCode(410, "Playback bootstrap has expired.");

        var opts = await _bunnyOptions.GetAsync(ct);
        if (string.IsNullOrEmpty(opts.EmbedTokenKey))
            return StatusCode(503, "Embed not configured.");

        var video = await _db.Videos.FirstOrDefaultAsync(v => v.Id == bootstrap.VideoId, ct);
        if (video is null) return NotFound("Video not found.");
        if (video.Status != VideoStatus.Ready) return Conflict(new { error = "Video is not ready for playback." });
        if (bootstrap.Kind == PublicPlaybackKind.Demo && !video.AllowPublicDemo)
            return StatusCode(403);

        // 4. Derive public user ID from privacy-preserving request material.
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = Request.Headers.UserAgent.ToString();
        var userId = CreatePublicUserId(opts, bootstrap, ip, ua);

        // 5. Ensure a short temporary VideoAccessGrant exists for the public viewer.
        var now = DateTimeOffset.UtcNow;
        var publicTtl = TimeSpan.FromMinutes(5);
        _db.VideoAccessGrants.Add(new VideoAccessGrant
        {
            UserId = userId,
            VideoId = bootstrap.VideoId,
            ExpiresAt = now.Add(publicTtl).AddMinutes(5)
        });
        await _db.SaveChangesAsync(ct);

        // 6. Create a playback session via the standard service
        PlaybackSessionResponse session;
        try
        {
            session = await _sessions.CreateAsync(userId, bootstrap.VideoId, ip, ua, publicTtl, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to create public playback session for video {VideoId}", bootstrap.VideoId);
            return StatusCode(500, "Failed to create playback session.");
        }

        var heartbeatToken = GenerateSecret();
        var playbackSession = await _db.PlaybackSessions.FirstAsync(s => s.Id == session.SessionId, ct);
        playbackSession.HeartbeatTokenHash = Sha256Hex(heartbeatToken);
        await _db.SaveChangesAsync(ct);

        return Ok(session with { HeartbeatToken = heartbeatToken });
    }

    private static string CreatePublicUserId(BunnyOptions opts, PublicPlaybackBootstrap bootstrap, string ip, string ua)
    {
        var secret = !string.IsNullOrWhiteSpace(opts.PrivacyHashPepper) ? opts.PrivacyHashPepper : opts.EmbedTokenKey;
        var material = $"{bootstrap.Kind}:{bootstrap.VideoId:N}:{bootstrap.Id}:{ip}:{ua}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
        return bootstrap.Kind == PublicPlaybackKind.Demo ? "demo:" + hash[..16] : "embed:" + hash[..16];
    }

    private static string GenerateSecret() =>
        Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    private void ApplyNoStoreHeaders()
    {
        Response.Headers.CacheControl = "no-store, private";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
    }

    private static bool TokenMatches(string? supplied, string expectedHash)
    {
        if (string.IsNullOrWhiteSpace(supplied)) return false;
        var suppliedHash = Sha256Hex(supplied);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(suppliedHash),
            Encoding.UTF8.GetBytes(expectedHash));
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

        // Only allow heartbeats for embed and demo sessions (not authenticated user sessions)
        if (!session.UserId.StartsWith("embed:", StringComparison.Ordinal) &&
            !session.UserId.StartsWith("demo:", StringComparison.Ordinal))
            return StatusCode(403);

        if (string.IsNullOrWhiteSpace(session.HeartbeatTokenHash) ||
            !TokenMatches(req.HeartbeatToken, session.HeartbeatTokenHash))
        {
            return StatusCode(403);
        }

        try
        {
            await _sessions.RecordHeartbeatAsync(req, session.UserId, ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (UnauthorizedAccessException) { return StatusCode(403); }
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
