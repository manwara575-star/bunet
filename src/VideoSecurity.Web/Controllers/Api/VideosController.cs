using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Route("api/videos")]
[Authorize]
public sealed class VideosController : ControllerBase
{
    private readonly IPlaybackSessionService _sessions;

    public VideosController(IPlaybackSessionService sessions) => _sessions = sessions;

    [HttpPost("{videoId:guid}/playback-session")]
    [EnableRateLimiting("session-create")]
    public async Task<ActionResult<PlaybackSessionResponse>> CreateSession(Guid videoId, CancellationToken ct)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? $"unknown:{HttpContext.TraceIdentifier}";
        var ua = Request.Headers.UserAgent.ToString();

        try
        {
            var resp = await _sessions.CreateAsync(userId, videoId, ip, ua, ct);
            return Ok(resp);
        }
        catch (UnauthorizedAccessException) { return Forbid(); }
        catch (InvalidOperationException ex) { return Conflict(new { error = ex.Message }); }
    }

    [HttpPost("heartbeat")]
    [EnableRateLimiting("heartbeat")]
    public async Task<ActionResult> Heartbeat([FromBody] HeartbeatRequest req, CancellationToken ct)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        try
        {
            await _sessions.RecordHeartbeatAsync(req, userId, ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (UnauthorizedAccessException) { return Forbid(); }
        catch (InvalidOperationException ex) { return Conflict(new { error = ex.Message }); }
    }
}
