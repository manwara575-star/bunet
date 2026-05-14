using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Controllers.Admin;

[Authorize(Policy = "SuperAdminOnly")]
public sealed class PoliciesController : Controller
{
    private readonly AppDbContext _db;
    private readonly IAuditLogService _audit;
    private readonly IBunnyOptionsProvider _options;

    public PoliciesController(AppDbContext db, IAuditLogService audit, IBunnyOptionsProvider options)
    {
        _db = db;
        _audit = audit;
        _options = options;
    }

    public sealed class PolicyEditViewModel
    {
        public Guid Id { get; set; }
        public VideoSensitivityTier Tier { get; set; }

        [Range(60, 3600)]
        public int EmbedTtlSeconds { get; set; }

        [Range(5, 120)]
        public int HeartbeatIntervalSeconds { get; set; }

        [Range(1, 10)]
        public int MaxConcurrentSessions { get; set; }

        public bool RequireWatermark { get; set; }
        public bool RevokeOnWatermarkTamper { get; set; }

        [Range(1, 100)]
        public int AutoRevokeRiskThreshold { get; set; }
    }

    [HttpGet("/admin/policies")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var rows = await _db.VideoSecurityPolicies.AsNoTracking()
            .OrderBy(p => p.Tier)
            .ToListAsync(ct);
        return View(rows);
    }

    [HttpGet("/admin/policies/{id:guid}/edit")]
    public async Task<IActionResult> Edit(Guid id, CancellationToken ct)
    {
        var p = await _db.VideoSecurityPolicies.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (p is null) return NotFound();
        return View(ToVm(p));
    }

    [HttpPost("/admin/policies/{id:guid}/edit")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(Guid id, PolicyEditViewModel vm, CancellationToken ct)
    {
        if (id != vm.Id) return BadRequest();
        if (!ModelState.IsValid) return View(vm);

        var entity = await _db.VideoSecurityPolicies.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (entity is null) return NotFound();

        var changes = new Dictionary<string, object?>();
        Track(changes, nameof(entity.EmbedTtlSeconds), entity.EmbedTtlSeconds, vm.EmbedTtlSeconds);
        Track(changes, nameof(entity.HeartbeatIntervalSeconds), entity.HeartbeatIntervalSeconds, vm.HeartbeatIntervalSeconds);
        Track(changes, nameof(entity.MaxConcurrentSessions), entity.MaxConcurrentSessions, vm.MaxConcurrentSessions);
        Track(changes, nameof(entity.RequireWatermark), entity.RequireWatermark, vm.RequireWatermark);
        Track(changes, nameof(entity.RevokeOnWatermarkTamper), entity.RevokeOnWatermarkTamper, vm.RevokeOnWatermarkTamper);
        Track(changes, nameof(entity.AutoRevokeRiskThreshold), entity.AutoRevokeRiskThreshold, vm.AutoRevokeRiskThreshold);

        entity.EmbedTtlSeconds = vm.EmbedTtlSeconds;
        entity.HeartbeatIntervalSeconds = vm.HeartbeatIntervalSeconds;
        entity.MaxConcurrentSessions = vm.MaxConcurrentSessions;
        entity.RequireWatermark = vm.RequireWatermark;
        entity.RevokeOnWatermarkTamper = vm.RevokeOnWatermarkTamper;
        entity.AutoRevokeRiskThreshold = vm.AutoRevokeRiskThreshold;

        await _db.SaveChangesAsync(ct);

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
        var opts = await _options.GetAsync(ct);
        await _audit.WriteAsync(
            actor,
            AuditAction.PolicyChanged,
            nameof(VideoSecurityPolicy),
            entity.Id.ToString(),
            new { tier = entity.Tier.ToString(), changes },
            AuditHashing.HashIp(opts, HttpContext),
            AuditHashing.HashUa(opts, HttpContext),
            ct);

        TempData["PolicyMessage"] = $"Updated policy for tier {entity.Tier} ({changes.Count} field(s) changed).";
        return RedirectToAction(nameof(Index));
    }

    private static void Track(Dictionary<string, object?> changes, string name, object? oldValue, object? newValue)
    {
        if (!Equals(oldValue, newValue))
            changes[name] = new { from = oldValue, to = newValue };
    }

    private static PolicyEditViewModel ToVm(VideoSecurityPolicy p) => new()
    {
        Id = p.Id,
        Tier = p.Tier,
        EmbedTtlSeconds = p.EmbedTtlSeconds,
        HeartbeatIntervalSeconds = p.HeartbeatIntervalSeconds,
        MaxConcurrentSessions = p.MaxConcurrentSessions,
        RequireWatermark = p.RequireWatermark,
        RevokeOnWatermarkTamper = p.RevokeOnWatermarkTamper,
        AutoRevokeRiskThreshold = p.AutoRevokeRiskThreshold
    };
}
