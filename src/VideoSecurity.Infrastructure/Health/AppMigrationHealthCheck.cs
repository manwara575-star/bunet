using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Health;

/// <summary>
/// Returns Healthy only if the database is reachable AND there are no pending EF Core migrations.
/// Tagged "ready" so it gates Kubernetes / load-balancer readiness probes.
/// </summary>
public sealed class AppMigrationHealthCheck : IHealthCheck
{
    private readonly AppDbContext _db;

    public AppMigrationHealthCheck(AppDbContext db)
    {
        _db = db;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Quick connectivity probe.
            await _db.Database.ExecuteSqlRawAsync("SELECT 1;", cancellationToken).ConfigureAwait(false);

            var pending = await _db.Database
                .GetPendingMigrationsAsync(cancellationToken)
                .ConfigureAwait(false);

            var pendingList = pending as IList<string> ?? pending.ToList();
            if (pendingList.Count > 0)
            {
                return HealthCheckResult.Unhealthy(
                    $"Pending EF Core migrations: {string.Join(", ", pendingList)}");
            }

            return HealthCheckResult.Healthy("Database reachable; no pending migrations.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database health probe failed.", ex);
        }
    }
}
