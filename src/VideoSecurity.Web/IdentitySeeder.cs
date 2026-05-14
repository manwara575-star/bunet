using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web;

public static class IdentitySeeder
{
    // "Admin" is the SuperAdmin alias retained for backward compatibility.
    public const string AdminRole = "Admin";
    public const string SuperAdminRole = "SuperAdmin";
    public const string VideoAdminRole = "VideoAdmin";
    public const string SecurityAuditorRole = "SecurityAuditor";
    public const string SupportAgentRole = "SupportAgent";

    public static readonly string[] AllRoles =
    {
        AdminRole,
        SuperAdminRole,
        VideoAdminRole,
        SecurityAuditorRole,
        SupportAgentRole
    };

    public static async Task SeedAsync(IServiceProvider sp, IConfiguration config)
    {
        var roles = sp.GetRequiredService<RoleManager<IdentityRole>>();
        var users = sp.GetRequiredService<UserManager<ApplicationUser>>();

        // Retain SuperAdmin role for legacy installs even though Admin is the canonical alias.
        await EnsureRoleAsync(roles, SuperAdminRole);
        foreach (var role in AllRoles)
        {
            await EnsureRoleAsync(roles, role);
        }

        var email = config["Seed:AdminEmail"];
        var password = config["Seed:AdminPassword"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return; // nothing to seed if not configured

        var existing = await users.FindByEmailAsync(email);
        if (existing is null)
        {
            existing = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                DisplayName = "Administrator"
            };
            var create = await users.CreateAsync(existing, password);
            if (!create.Succeeded)
            {
                existing = await users.FindByEmailAsync(email);
                if (existing is null)
                    throw new InvalidOperationException("Seed admin failed: " + string.Join("; ", create.Errors.Select(e => e.Description)));
            }
        }
        if (!await users.IsInRoleAsync(existing, AdminRole))
            await users.AddToRoleAsync(existing, AdminRole);

        if (config.GetValue<bool>("Seed:E2EReadyVideo"))
        {
            var db = sp.GetRequiredService<AppDbContext>();
            var bunnyVideoId = config["Seed:E2EReadyVideoBunnyId"] ?? "e2e-ready-video";
            var title = config["Seed:E2EReadyVideoTitle"] ?? "E2E Ready Video";
            var video = await db.Videos.FirstOrDefaultAsync(v => v.BunnyVideoId == bunnyVideoId);
            if (video is null)
            {
                db.Videos.Add(new Video
                {
                    Title = title,
                    Description = "Seeded only when Seed:E2EReadyVideo is enabled.",
                    BunnyLibraryId = config.GetValue<long?>("Bunny:LibraryId") ?? 0,
                    BunnyVideoId = bunnyVideoId,
                    Status = VideoStatus.Ready,
                    CreatedByUserId = existing.Id,
                    DurationSeconds = 120
                });
            }
            else
            {
                video.Title = title;
                video.BunnyLibraryId = config.GetValue<long?>("Bunny:LibraryId") ?? video.BunnyLibraryId;
                video.Status = VideoStatus.Ready;
                video.CreatedByUserId = existing.Id;
                video.DurationSeconds = video.DurationSeconds <= 0 ? 120 : video.DurationSeconds;
                video.UpdatedAt = DateTimeOffset.UtcNow;
            }

            await db.SaveChangesAsync();
        }
    }

    private static async Task EnsureRoleAsync(RoleManager<IdentityRole> roles, string role)
    {
        if (await roles.RoleExistsAsync(role)) return;

        var create = await roles.CreateAsync(new IdentityRole(role));
        if (!create.Succeeded && !await roles.RoleExistsAsync(role))
            throw new InvalidOperationException("Seed role failed: " + string.Join("; ", create.Errors.Select(e => e.Description)));
    }
}
