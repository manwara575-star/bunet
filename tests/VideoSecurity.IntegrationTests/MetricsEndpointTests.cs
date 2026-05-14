using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.IntegrationTests;

public sealed class MetricsEndpointTests : IClassFixture<BunnyMockFactory>
{
    private readonly BunnyMockFactory _f;
    public MetricsEndpointTests(BunnyMockFactory f) => _f = f;

    [Fact]
    public async Task AppMetricsEndpoint_ReturnsPrometheusFormat()
    {
        var client = _f.CreateClient();
        var resp = await client.GetAsync("/metrics/app");
        resp.IsSuccessStatusCode.Should().BeTrue();
        resp.Content.Headers.ContentType?.MediaType.Should().StartWith("text/plain");
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("# HELP");
        body.Should().Contain("videosecurity_active_playback_sessions");
    }

    [Fact]
    public async Task AppMetricsEndpoint_CountsOnlyActiveSessions_WithSameDayExpiryBounds()
    {
        var client = _f.CreateClient();
        var before = ParseMetric(await client.GetStringAsync("/metrics/app"), "videosecurity_active_playback_sessions");
        var now = DateTimeOffset.UtcNow;

        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.PlaybackSessions.AddRange(
                new PlaybackSession
                {
                    UserId = "metrics-active",
                    VideoId = Guid.NewGuid(),
                    CreatedAt = now.AddMinutes(-5),
                    ExpiresAt = now.AddMinutes(10),
                    IpHash = "ip",
                    UserAgentHash = "ua",
                    WatermarkPayload = "wm"
                },
                new PlaybackSession
                {
                    UserId = "metrics-expired",
                    VideoId = Guid.NewGuid(),
                    CreatedAt = now.AddMinutes(-10),
                    ExpiresAt = now.AddMinutes(-1),
                    IpHash = "ip",
                    UserAgentHash = "ua",
                    WatermarkPayload = "wm"
                });
            await db.SaveChangesAsync();
        }

        var after = ParseMetric(await client.GetStringAsync("/metrics/app"), "videosecurity_active_playback_sessions");
        after.Should().Be(before + 1);
    }

    private static long ParseMetric(string body, string metricName)
    {
        var line = body.Split('\n').Single(l => l.StartsWith(metricName + " ", StringComparison.Ordinal));
        return long.Parse(line[(metricName.Length + 1)..], System.Globalization.CultureInfo.InvariantCulture);
    }
}
