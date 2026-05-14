using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Observability;

public sealed class SecurityMetrics : IDisposable
{
    public const string MeterName = "VideoSecurity.Security";

    private readonly Meter _meter;
    private readonly bool _disabled;
    private readonly IServiceProvider? _sp;

    private readonly Counter<long>? _sessionsCreated;
    private readonly Counter<long>? _sessionsDenied;
    private readonly Counter<long>? _sessionsRevoked;
    private readonly Counter<long>? _heartbeats;
    private readonly Counter<long>? _securityEvents;
    private readonly Counter<long>? _watermarkTamper;
    private readonly Counter<long>? _entitlementDenials;
    private readonly Counter<long>? _autoRevokes;
    private readonly Counter<long>? _concurrentLimit;
    private readonly Counter<long>? _webhookReceived;
    private readonly Counter<long>? _webhookFailed;
    private readonly Histogram<double>? _heartbeatLag;

    public SecurityMetrics(IServiceProvider sp)
    {
        _sp = sp ?? throw new ArgumentNullException(nameof(sp));
        _meter = new Meter(MeterName, "1.0.0");

        _sessionsCreated = _meter.CreateCounter<long>(
            "videosecurity_playback_sessions_created_total",
            description: "Playback sessions successfully created.");
        _sessionsDenied = _meter.CreateCounter<long>(
            "videosecurity_playback_sessions_denied_total",
            description: "Playback session creation attempts denied.");
        _sessionsRevoked = _meter.CreateCounter<long>(
            "videosecurity_playback_sessions_revoked_total",
            description: "Playback sessions revoked (any reason).");
        _heartbeats = _meter.CreateCounter<long>(
            "videosecurity_playback_heartbeats_total",
            description: "Heartbeat requests successfully processed.");
        _securityEvents = _meter.CreateCounter<long>(
            "videosecurity_security_events_total",
            description: "Security events recorded, tagged by type.");
        _watermarkTamper = _meter.CreateCounter<long>(
            "videosecurity_watermark_tamper_total",
            description: "Watermark tamper events detected.");
        _entitlementDenials = _meter.CreateCounter<long>(
            "videosecurity_entitlement_denials_total",
            description: "Entitlement denial events.");
        _autoRevokes = _meter.CreateCounter<long>(
            "videosecurity_auto_revokes_total",
            description: "Sessions auto-revoked due to risk threshold.");
        _concurrentLimit = _meter.CreateCounter<long>(
            "videosecurity_concurrent_limit_revokes_total",
            description: "Sessions revoked because of concurrent-session limit.");
        _webhookReceived = _meter.CreateCounter<long>(
            "videosecurity_webhooks_received_total",
            description: "Bunny webhooks received.");
        _webhookFailed = _meter.CreateCounter<long>(
            "videosecurity_webhooks_failed_total",
            description: "Bunny webhooks rejected/failed.");
        _heartbeatLag = _meter.CreateHistogram<double>(
            "videosecurity_heartbeat_lag_seconds",
            unit: "s",
            description: "Observed lag between successive heartbeats per session.");

        _meter.CreateObservableGauge(
            "videosecurity_active_playback_sessions",
            () => SafeQuery(db =>
            {
                var nowTicks = DateTimeOffset.UtcNow.UtcDateTime.Ticks;
                return db.PlaybackSessions.Count(s => !s.Revoked && s.ExpiresAtUtcTicks > nowTicks);
            }),
            description: "Active non-revoked playback sessions.");

        _meter.CreateObservableGauge(
            "videosecurity_revoked_playback_sessions",
            () => SafeQuery(db => db.PlaybackSessions.AsNoTracking().Count(s => s.Revoked)),
            description: "Revoked playback sessions.");

        _meter.CreateObservableGauge(
            "videosecurity_ready_videos",
            () => SafeQuery(db => db.Videos.AsNoTracking().Count(v => v.Status == VideoStatus.Ready)),
            description: "Videos currently marked Ready.");
    }

    private SecurityMetrics(bool disabled)
    {
        _disabled = true;
        _meter = new Meter(MeterName + ".NoOp", "1.0.0");
    }

    /// <summary>
    /// Returns a no-op instance suitable for unit tests. Record* calls are silently dropped
    /// and no observable gauges are registered.
    /// </summary>
    public static SecurityMetrics NoOp() => new(disabled: true);

    private long SafeQuery(Func<AppDbContext, int> query)
    {
        if (_disabled || _sp is null) return 0;
        try
        {
            using var scope = _sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            return query(db);
        }
        catch
        {
            return 0;
        }
    }

    public void RecordSessionCreated()
    {
        if (_disabled) return;
        _sessionsCreated!.Add(1);
    }
    public void RecordSessionDenied(string reason)
    {
        if (_disabled) return;
        _sessionsDenied!.Add(1, new KeyValuePair<string, object?>("reason", reason));
    }
    public void RecordSessionRevoked(string reason)
    {
        if (_disabled) return;
        _sessionsRevoked!.Add(1, new KeyValuePair<string, object?>("reason", reason));
    }
    public void RecordHeartbeat()
    {
        if (_disabled) return;
        _heartbeats!.Add(1);
    }
    public void RecordSecurityEvent(string eventType)
    {
        if (_disabled) return;
        _securityEvents!.Add(1, new KeyValuePair<string, object?>("type", eventType));
    }
    public void RecordWatermarkTamper()
    {
        if (_disabled) return;
        _watermarkTamper!.Add(1);
    }
    public void RecordEntitlementDenied()
    {
        if (_disabled) return;
        _entitlementDenials!.Add(1);
    }
    public void RecordAutoRevoke(string trigger)
    {
        if (_disabled) return;
        _autoRevokes!.Add(1, new KeyValuePair<string, object?>("trigger", trigger));
    }
    public void RecordConcurrentLimit()
    {
        if (_disabled) return;
        _concurrentLimit!.Add(1);
    }
    public void RecordWebhookReceived(string outcome)
    {
        if (_disabled) return;
        _webhookReceived!.Add(1, new KeyValuePair<string, object?>("outcome", outcome));
    }
    public void RecordWebhookFailed(string reason)
    {
        if (_disabled) return;
        _webhookFailed!.Add(1, new KeyValuePair<string, object?>("reason", reason));
    }
    public void RecordHeartbeatLag(double seconds)
    {
        if (_disabled) return;
        _heartbeatLag!.Record(seconds);
    }

    public void Dispose() => _meter.Dispose();
}

