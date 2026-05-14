using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers.Admin;

[Authorize(Policy = "SecurityAuditorOnly")]
public sealed class AuditLogController : Controller
{
    private const int PageSize = 50;
    private readonly AppDbContext _db;

    public AuditLogController(AppDbContext db) => _db = db;

    public sealed class IndexViewModel
    {
        public IReadOnlyList<AuditLog> Rows { get; init; } = Array.Empty<AuditLog>();
        public int Page { get; init; }
        public int TotalPages { get; init; }
        public string? Actor { get; init; }
        public string? Action { get; init; }
        public DateTimeOffset? From { get; init; }
        public DateTimeOffset? To { get; init; }
    }

    [HttpGet("/admin/audit")]
    public async Task<IActionResult> Index(
        string? actor,
        string? action,
        DateTimeOffset? from,
        DateTimeOffset? to,
        int page = 1,
        CancellationToken ct = default)
    {
        if (page < 1) page = 1;

        var actorFilter = string.IsNullOrWhiteSpace(actor) ? null : actor;
        var actionFilter = !string.IsNullOrWhiteSpace(action) && Enum.TryParse<AuditAction>(action, true, out var parsed)
            ? (int?)parsed
            : null;
        var fromTicks = from?.UtcDateTime.Ticks;
        var toTicks = to?.UtcDateTime.Ticks;

        var filteredQuery = _db.AuditLogs.AsNoTracking().AsQueryable();
        if (actorFilter is not null)
            filteredQuery = filteredQuery.Where(a => a.ActorUserId == actorFilter);
        if (actionFilter is not null)
            filteredQuery = filteredQuery.Where(a => (int)a.Action == actionFilter.Value);
        if (fromTicks is not null)
            filteredQuery = filteredQuery.Where(a => a.CreatedAtUtcTicks >= fromTicks.Value);
        if (toTicks is not null)
            filteredQuery = filteredQuery.Where(a => a.CreatedAtUtcTicks <= toTicks.Value);

        var total = await filteredQuery.CountAsync(ct);
        var totalPages = Math.Max(1, (int)Math.Ceiling(total / (double)PageSize));
        if (page > totalPages) page = totalPages;

                var rows = await filteredQuery.OrderByDescending(a => a.CreatedAtUtcTicks)
                        .Skip((page - 1) * PageSize)
                        .Take(PageSize)
                        .ToListAsync(ct);

        return View(new IndexViewModel
        {
            Rows = rows,
            Page = page,
            TotalPages = totalPages,
            Actor = actor,
            Action = action,
            From = from,
            To = to
        });
    }
}
