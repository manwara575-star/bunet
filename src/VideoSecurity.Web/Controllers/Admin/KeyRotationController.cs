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
public sealed class KeyRotationController : Controller
{
    private readonly AppDbContext _db;
    private readonly IAuditLogService _audit;
    private readonly IBunnyOptionsProvider _options;

    public KeyRotationController(AppDbContext db, IAuditLogService audit, IBunnyOptionsProvider options)
    {
        _db = db;
        _audit = audit;
        _options = options;
    }

    [HttpGet("/admin/keys")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var rows = await _db.SigningKeyVersions.AsNoTracking()
            .OrderBy(k => k.Purpose).ThenByDescending(k => k.Version)
            .ToListAsync(ct);
        return View(rows);
    }

    [HttpPost("/admin/keys/rotate")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Rotate(SigningKeyPurpose purpose, string? notes, CancellationToken ct)
    {
        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        var current = await _db.SigningKeyVersions
            .Where(k => k.Purpose == purpose && k.IsActive)
            .ToListAsync(ct);
        var fromVersion = 0;
        var now = DateTimeOffset.UtcNow;
        foreach (var c in current)
        {
            c.IsActive = false;
            c.RetiredAt = now;
            if (c.Version > fromVersion) fromVersion = c.Version;
        }

        var maxVersion = await _db.SigningKeyVersions
            .Where(k => k.Purpose == purpose)
            .Select(k => (int?)k.Version)
            .MaxAsync(ct) ?? 0;
        var toVersion = maxVersion + 1;

        _db.SigningKeyVersions.Add(new SigningKeyVersion
        {
            Purpose = purpose,
            Version = toVersion,
            IsActive = true,
            CreatedAt = now,
            Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim()
        });

        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
    var opts = await _options.GetAsync(ct);
        await _audit.WriteAsync(
            actor,
            AuditAction.KeyRotated,
            nameof(SigningKeyVersion),
            purpose.ToString(),
            new { purpose = purpose.ToString(), fromVersion, toVersion },
            AuditHashing.HashIp(opts, HttpContext),
            AuditHashing.HashUa(opts, HttpContext),
            ct);

        TempData["KeyRotationMessage"] = $"Recorded rotation of {purpose} from v{fromVersion} to v{toVersion}.";
        return RedirectToAction(nameof(Index));
    }
}
