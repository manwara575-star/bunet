using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Services;

public sealed class PolicySeederHostedService : IHostedService
{
    private readonly IServiceProvider _sp;

    public PolicySeederHostedService(IServiceProvider sp) => _sp = sp;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Skip seeding when the schema is not present (e.g. early startup before migrations).
        try
        {
            var existing = await db.VideoSecurityPolicies
                .Select(p => p.Tier)
                .ToListAsync(cancellationToken);

            var tiers = new[]
            {
                VideoSensitivityTier.Standard,
                VideoSensitivityTier.Premium,
                VideoSensitivityTier.Critical
            };

            var added = false;
            foreach (var tier in tiers)
            {
                if (existing.Contains(tier)) continue;
                db.VideoSecurityPolicies.Add(VideoSecurityPolicyService.DefaultFor(tier));
                added = true;
            }

            if (added) await db.SaveChangesAsync(cancellationToken);
        }
        catch
        {
            // Migrations may not yet be applied at startup in some hosts; ignore.
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
