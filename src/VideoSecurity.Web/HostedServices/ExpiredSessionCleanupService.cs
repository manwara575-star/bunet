using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.HostedServices;

/// <summary>
/// Periodically marks expired playback sessions as revoked and prunes very old security events.
/// Runs every 5 minutes. Idempotent and bounded per pass to avoid long transactions on busy DBs.
/// </summary>
public sealed class ExpiredSessionCleanupService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
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
        var secureOptions = scope.ServiceProvider.GetService<IOptions<SecurePlaybackOptions>>()?.Value ?? new SecurePlaybackOptions();
        var now = DateTimeOffset.UtcNow;
        var nowTicks = now.UtcDateTime.Ticks;

        // Revoke expired but not-yet-revoked sessions (bounded batch).
        var expired = await db.PlaybackSessions
            .Where(s => !s.Revoked && s.ExpiresAtUtcTicks <= nowTicks)
            .OrderBy(s => s.ExpiresAtUtcTicks)
            .Take(BatchSize)
            .ToListAsync(stoppingToken);

        foreach (var s in expired)
        {
            s.Revoked = true;
            s.RevocationReason = "expired";
            s.RevokedAt = now;
            if (secureWorker is not null)
                await secureWorker.StopAsync(s.Id, stoppingToken);
        }

        var staleCutoff = now - secureOptions.StaleSessionTimeout;
        var staleCutoffTicks = staleCutoff.UtcDateTime.Ticks;
        var staleSecure = await db.PlaybackSessions
            .Where(s =>
                !s.Revoked &&
                s.HeartbeatTokenHash != null &&
                ((s.LastHeartbeatAtUtcTicks > 0 && s.LastHeartbeatAtUtcTicks <= staleCutoffTicks) ||
                 (s.LastHeartbeatAtUtcTicks == 0 && s.CreatedAtUtcTicks <= staleCutoffTicks)))
            .OrderBy(s => s.LastHeartbeatAtUtcTicks > 0 ? s.LastHeartbeatAtUtcTicks : s.CreatedAtUtcTicks)
            .Take(BatchSize)
            .ToListAsync(stoppingToken);

        foreach (var s in staleSecure)
        {
            s.Revoked = true;
            s.RevocationReason = "stale-heartbeat";
            s.RevokedAt = now;
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

        if (expired.Count > 0 || staleSecure.Count > 0 || deleted > 0 || deletedReceipts > 0)
            await db.SaveChangesAsync(stoppingToken);

        if (expired.Count > 0 || staleSecure.Count > 0 || deleted > 0 || deletedReceipts > 0)
            _log.LogInformation(
                "Cleanup pass: revoked {Revoked} expired sessions, revoked {StaleSecure} stale secure sessions, pruned {Deleted} old events, pruned {DeletedReceipts} webhook receipts",
                expired.Count,
                staleSecure.Count,
                deleted,
                deletedReceipts);
    }
}
