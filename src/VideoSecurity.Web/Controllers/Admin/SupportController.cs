using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers.Admin;

[Authorize(Policy = "SupportAgentOnly")]
public sealed class SupportController : Controller
{
    private readonly AppDbContext _db;

    public SupportController(AppDbContext db) => _db = db;

    [HttpGet("/admin/support")]
    public async Task<IActionResult> Index(string? userId, CancellationToken ct)
    {
        var nowTicks = DateTimeOffset.UtcNow.UtcDateTime.Ticks;

        var sessionsQuery = _db.PlaybackSessions.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(userId))
            sessionsQuery = sessionsQuery.Where(s => s.UserId == userId);

        var sessions = await sessionsQuery
            .OrderByDescending(s => s.CreatedAtUtcTicks)
            .Take(100)
            .Select(s => new SupportSessionRow(
                s.Id,
                s.UserId,
                s.VideoId,
                s.CreatedAt,
                s.ExpiresAt,
                s.Revoked,
                s.RiskScore,
                s.LastKnownPositionSeconds))
            .ToListAsync(ct);

        var progressQuery = _db.VideoProgress.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(userId))
            progressQuery = progressQuery.Where(p => p.UserId == userId);

        var progress = await progressQuery
            .OrderByDescending(p => p.UpdatedAt)
            .Take(100)
            .Select(p => new SupportProgressRow(
                p.UserId,
                p.VideoId,
                p.LastPositionSeconds,
                p.FurthestPositionSeconds,
                p.Completed,
                p.UpdatedAt))
            .ToListAsync(ct);

        ViewData["FilteredUserId"] = userId;
        return View(new SupportDashboardModel(sessions, progress));
    }

    public sealed record SupportSessionRow(
        Guid SessionId, string UserId, Guid VideoId,
        DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt,
        bool Revoked, int RiskScore, double LastPosition);

    public sealed record SupportProgressRow(
        string UserId, Guid VideoId,
        double LastPosition, double FurthestPosition,
        bool Completed, DateTimeOffset UpdatedAt);

    public sealed record SupportDashboardModel(
        List<SupportSessionRow> Sessions,
        List<SupportProgressRow> Progress);
}
