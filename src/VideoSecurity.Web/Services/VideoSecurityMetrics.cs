using System.Diagnostics.Metrics;

namespace VideoSecurity.Web.Services;

public static class VideoSecurityMetrics
{
    public const string MeterName = "VideoSecurity";

    private static readonly Meter Meter = new(MeterName, "1.0.0");

    public static readonly Counter<long> AdminActions = Meter.CreateCounter<long>(
        "videosecurity_admin_actions_total",
        description: "Administrative actions recorded in the audit log.");
}
