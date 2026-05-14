using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Route("api/security/video-events")]
[EnableRateLimiting("anon-events")]
[IgnoreAntiforgeryToken]
public sealed class SecurityEventsController : ControllerBase
{
    private readonly ISecurityEventService _events;

    public SecurityEventsController(ISecurityEventService events) => _events = events;

    /// <summary>
    /// Best-effort telemetry from the player. Allowed anonymously so we still capture events
    /// from a session that lost auth, but rate-limited per IP via standard middleware in prod.
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [RequestSizeLimit(16 * 1024)]
    public async Task<ActionResult> Post([FromBody] SecurityEventRequest req, CancellationToken ct)
    {
        if (req is null || string.IsNullOrWhiteSpace(req.Type)) return BadRequest();

        var userId = User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            req = req with { SessionId = null, VideoId = null };

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? $"unknown:{HttpContext.TraceIdentifier}";
        var ua = Request.Headers.UserAgent.ToString();
        await _events.RecordAsync(req, userId, ip, ua, ct);
        return Accepted();
    }
}
