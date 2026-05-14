using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Controllers.Admin;

[Authorize(Policy = "SuperAdminOnly")]
public sealed class RolesController : Controller
{
    private const int PageSize = 25;

    private readonly UserManager<ApplicationUser> _users;
    private readonly IAuditLogService _audit;
    private readonly IBunnyOptionsProvider _options;

    public RolesController(UserManager<ApplicationUser> users, IAuditLogService audit, IBunnyOptionsProvider options)
    {
        _users = users;
        _audit = audit;
        _options = options;
    }

    public sealed record UserRow(string Id, string? Email, string? UserName, IList<string> Roles);
    public sealed class IndexViewModel
    {
        public IReadOnlyList<UserRow> Users { get; init; } = Array.Empty<UserRow>();
        public int Page { get; init; }
        public int TotalPages { get; init; }
        public IReadOnlyList<string> AvailableRoles { get; init; } = Array.Empty<string>();
    }

    [HttpGet("/admin/roles")]
    public async Task<IActionResult> Index(int page = 1, CancellationToken ct = default)
    {
        if (page < 1) page = 1;
        var total = await _users.Users.CountAsync(ct);
        var totalPages = Math.Max(1, (int)Math.Ceiling(total / (double)PageSize));
        if (page > totalPages) page = totalPages;

        var slice = await _users.Users
            .OrderBy(u => u.UserName)
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync(ct);

        var rows = new List<UserRow>(slice.Count);
        foreach (var u in slice)
        {
            var roles = await _users.GetRolesAsync(u);
            rows.Add(new UserRow(u.Id, u.Email, u.UserName, roles));
        }

        return View(new IndexViewModel
        {
            Users = rows,
            Page = page,
            TotalPages = totalPages,
            AvailableRoles = IdentitySeeder.AllRoles
        });
    }

    [HttpPost("/admin/roles/grant")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Grant(string userId, string role, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(role))
            return BadRequest("userId and role are required.");
        if (!IdentitySeeder.AllRoles.Contains(role, StringComparer.Ordinal))
            return BadRequest("Unknown role.");

        var user = await _users.FindByIdAsync(userId);
        if (user is null) return NotFound();

        if (!await _users.IsInRoleAsync(user, role))
        {
            var result = await _users.AddToRoleAsync(user, role);
            if (!result.Succeeded)
            {
                TempData["RoleMessage"] = "Grant failed: " + string.Join("; ", result.Errors.Select(e => e.Description));
                return RedirectToAction(nameof(Index));
            }
            await WriteAuditAsync(userId, "grant", role, ct);
        }

        TempData["RoleMessage"] = $"Granted {role} to {user.UserName}.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost("/admin/roles/revoke")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(string userId, string role, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(role))
            return BadRequest("userId and role are required.");
        if (!IdentitySeeder.AllRoles.Contains(role, StringComparer.Ordinal))
            return BadRequest("Unknown role.");

        var user = await _users.FindByIdAsync(userId);
        if (user is null) return NotFound();

        // Safety guard: refuse to revoke the last Admin user.
        if (string.Equals(role, IdentitySeeder.AdminRole, StringComparison.Ordinal))
        {
            var admins = await _users.GetUsersInRoleAsync(IdentitySeeder.AdminRole);
            if (admins.Count <= 1 && admins.Any(a => a.Id == userId))
            {
                TempData["RoleMessage"] = "Refused: cannot revoke the last Admin user.";
                return RedirectToAction(nameof(Index));
            }
        }

        if (await _users.IsInRoleAsync(user, role))
        {
            var result = await _users.RemoveFromRoleAsync(user, role);
            if (!result.Succeeded)
            {
                TempData["RoleMessage"] = "Revoke failed: " + string.Join("; ", result.Errors.Select(e => e.Description));
                return RedirectToAction(nameof(Index));
            }
            await WriteAuditAsync(userId, "revoke", role, ct);
        }

        TempData["RoleMessage"] = $"Revoked {role} from {user.UserName}.";
        return RedirectToAction(nameof(Index));
    }

    private async Task WriteAuditAsync(string userId, string action, string role, CancellationToken ct)
    {
        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
        var opts = await _options.GetAsync(ct);
        await _audit.WriteAsync(
            actor,
            AuditAction.RoleChanged,
            "User",
            userId,
            new { userId, action, role },
            AuditHashing.HashIp(opts, HttpContext),
            AuditHashing.HashUa(opts, HttpContext),
            ct);
    }
}
