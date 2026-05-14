using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers;

[Authorize]
public sealed class PlayerController : Controller
{
    private readonly AppDbContext _db;
    private readonly IVideoEntitlementService _entitlement;

    public PlayerController(AppDbContext db, IVideoEntitlementService entitlement)
    {
        _db = db;
        _entitlement = entitlement;
    }

    [HttpGet("/player/watch/{id:guid}")]
    public async Task<IActionResult> Watch(Guid id, CancellationToken ct)
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return Forbid();

        var video = await _db.Videos.AsNoTracking().FirstOrDefaultAsync(v => v.Id == id, ct);
        if (video is null) return NotFound();
        if (video.Status != VideoStatus.Ready) return View("NotReady", video);

        if (!await _entitlement.IsAuthorizedAsync(userId, id, ct))
            return Forbid();

        // Note: NO embed URL is rendered server-side. The browser fetches it via /api/videos/{id}/playback-session
        // so it never lands in static HTML / SSR / logs.
        ViewBag.VideoId = id;
        ViewBag.Title = video.Title;
        return View();
    }
}
