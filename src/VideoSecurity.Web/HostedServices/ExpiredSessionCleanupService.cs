using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.HostedServices;

/// <summary>
/// Periodically marks expired playback sessions as revoked and prunes very old security events.
/// Runs every 5 minutes. Idempotent and bounded per pass to avoid long transactions on busy DBs.
/// </summary>
public sealed class ExpiredSessionCleanupService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan EventRetention = TimeSpan.FromDays(90);
    private static readonly TimeSpan WebhookReceiptRetention = TimeSpan.FromDays(14);
    private const int BatchSize = 500;

    private readonly IServiceProvider _sp;
    private readonly ILogger<ExpiredSessionCleanupService> _log;

    public ExpiredSessionCleanupService(IServiceProvider sp, ILogger<ExpiredSessionCleanupService> log)
    {
        _sp = sp;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Stagger first pass slightly so app startup isn't bottlenecked by it.
        try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); } catch { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "ExpiredSessionCleanupService pass failed");
            }

            try { await Task.Delay(Interval, stoppingToken); } catch { break; }
        }
    }

    public async Task RunOnceAsync(CancellationToken stoppingToken)
    {
        await using var scope = _sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var secureWorker = scope.ServiceProvider.GetService<ISecureMediaWorker>();
        var now = DateTimeOffset.UtcNow;

        // Revoke expired but not-yet-revoked sessions (bounded batch).
        var expired = await db.PlaybackSessions
            .Where(s => !s.Revoked)
            .ToListAsync(stoppingToken);
        expired = expired.Where(s => s.ExpiresAt <= now).OrderBy(s => s.ExpiresAt).Take(BatchSize).ToList();

        foreach (var s in expired)
        {
            s.Revoked = true;
            s.RevocationReason = "expired";
            if (secureWorker is not null)
                await secureWorker.StopAsync(s.Id, stoppingToken);
        }

        // Prune ancient telemetry.
        var cutoff = now - EventRetention;
        var oldEvents = await db.VideoSecurityEvents.ToListAsync(stoppingToken);
        oldEvents = oldEvents.Where(e => e.CreatedAt < cutoff).Take(BatchSize).ToList();
        db.VideoSecurityEvents.RemoveRange(oldEvents);
        var deleted = oldEvents.Count;

        var webhookCutoff = now - WebhookReceiptRetention;
        var oldReceipts = await db.BunnyWebhookReceipts.ToListAsync(stoppingToken);
        oldReceipts = oldReceipts.Where(e => e.ReceivedAt < webhookCutoff).Take(BatchSize).ToList();
        db.BunnyWebhookReceipts.RemoveRange(oldReceipts);
        var deletedReceipts = oldReceipts.Count;

        if (expired.Count > 0 || deleted > 0 || deletedReceipts > 0)
            await db.SaveChangesAsync(stoppingToken);

        if (expired.Count > 0 || deleted > 0 || deletedReceipts > 0)
            _log.LogInformation("Cleanup pass: revoked {Revoked} expired sessions, pruned {Deleted} old events, pruned {DeletedReceipts} webhook receipts", expired.Count, deleted, deletedReceipts);
    }
}
