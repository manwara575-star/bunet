using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Bunny;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.HostedServices;
using Microsoft.Extensions.Options;

namespace VideoSecurity.IntegrationTests;

/// <summary>
/// Forks the BunnyMockFactory to enable a webhook secret so we can validate
/// reject-on-bad-secret behavior.
/// </summary>
public sealed class WebhookSecretFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var contentRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "VideoSecurity.Web"));
        if (Directory.Exists(contentRoot)) builder.UseContentRoot(contentRoot);
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = $"DataSource=file:wh_{Guid.NewGuid():N}?mode=memory&cache=shared",
                ["Bunny:LibraryId"] = "999",
                ["Bunny:ApiKey"] = "webhook-api-key-for-tests-only-32chars",
                ["Bunny:EmbedTokenKey"] = "webhook-embed-key-for-tests-only-32",
                ["Bunny:CdnHostname"] = "vz-test.b-cdn.net",
                ["Bunny:WebhookSecret"] = "the-webhook-secret-value"
            });
        });
    }
}

public class WebhookAuthTests : IClassFixture<WebhookSecretFactory>
{
    private readonly WebhookSecretFactory _f;
    public WebhookAuthTests(WebhookSecretFactory f) => _f = f;

    [Fact]
    public async Task Webhook_RejectsMissingSecret_When401()
    {
        var c = _f.CreateClient();
        var resp = await c.PostAsJsonAsync("/api/webhooks/bunny/stream", new { videoLibraryId = "999", videoGuid = "g", status = 4 });
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Webhook_RejectsWrongSecret()
    {
        var c = _f.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream")
        {
            Content = JsonContent.Create(new { videoLibraryId = "999", videoGuid = "g", status = 4 })
        };
        req.Headers.Add("X-Bunny-Webhook-Secret", "wrong");
        var resp = await c.SendAsync(req);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Webhook_AcceptsCorrectSecret()
    {
        var c = _f.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream")
        {
            Content = JsonContent.Create(new { videoLibraryId = "999", videoGuid = "g", status = 4 })
        };
        req.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        var resp = await c.SendAsync(req);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);
    }

    [Fact]
    public async Task Webhook_AcceptsOfficialBunnyStreamSignature()
    {
        var c = _f.CreateClient();
        const string raw = "{\"videoLibraryId\":\"999\",\"videoGuid\":\"g\",\"status\":4}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("webhook-api-key-for-tests-only-32chars"));
        var sig = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream")
        {
            Content = new StringContent(raw, Encoding.UTF8, "application/json")
        };
        req.Headers.Add("X-BunnyStream-Signature-Version", "v1");
        req.Headers.Add("X-BunnyStream-Signature-Algorithm", "hmac-sha256");
        req.Headers.Add("X-BunnyStream-Signature", sig);

        var resp = await c.SendAsync(req);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);
    }

    [Fact]
    public async Task Webhook_RejectsWrongLibraryId()
    {
        var c = _f.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream")
        {
            Content = JsonContent.Create(new { videoLibraryId = "998", videoGuid = "g", status = 4 })
        };
        req.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");

        var resp = await c.SendAsync(req);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Webhook_DoesNotDowngradeReadyVideoToFailed()
    {
        var bunnyVideoId = "ready-video-" + Guid.NewGuid().ToString("N");
        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = Guid.NewGuid(),
                Title = "Ready",
                BunnyLibraryId = 999,
                BunnyVideoId = bunnyVideoId,
                Status = VideoStatus.Ready,
                CreatedByUserId = "admin"
            });
            await db.SaveChangesAsync();
        }

        var c = _f.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream")
        {
            Content = JsonContent.Create(new { videoLibraryId = "999", videoGuid = bunnyVideoId, status = 5 })
        };
        req.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        var resp = await c.SendAsync(req);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);

        using var verifyScope = _f.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var video = await verifyDb.Videos.SingleAsync(v => v.BunnyVideoId == bunnyVideoId);
        video.Status.Should().Be(VideoStatus.Ready);
    }

    [Fact]
    public async Task Webhook_Status3_RemainsProcessingUntilFinishedStatus4()
    {
        var bunnyVideoId = "processing-video-" + Guid.NewGuid().ToString("N");
        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = Guid.NewGuid(),
                Title = "Processing",
                BunnyLibraryId = 999,
                BunnyVideoId = bunnyVideoId,
                Status = VideoStatus.Processing,
                CreatedByUserId = "admin"
            });
            await db.SaveChangesAsync();
        }

        var c = _f.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream")
        {
            Content = JsonContent.Create(new { videoLibraryId = "999", videoGuid = bunnyVideoId, status = 3 })
        };
        req.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        var resp = await c.SendAsync(req);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);

        using var verifyScope = _f.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var video = await verifyDb.Videos.SingleAsync(v => v.BunnyVideoId == bunnyVideoId);
        video.Status.Should().Be(VideoStatus.Processing);
    }

    [Fact]
    public async Task Webhook_DuplicateBody_IsAcceptedButIgnored()
    {
        var bunnyVideoId = "dupe-video-" + Guid.NewGuid().ToString("N");
        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = Guid.NewGuid(),
                Title = "Dupe",
                BunnyLibraryId = 999,
                BunnyVideoId = bunnyVideoId,
                Status = VideoStatus.Processing,
                CreatedByUserId = "admin"
            });
            await db.SaveChangesAsync();
        }

        var c = _f.CreateClient();
        var body = new { videoLibraryId = "999", videoGuid = bunnyVideoId, status = 4 };
        var first = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream") { Content = JsonContent.Create(body) };
        first.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        (await c.SendAsync(first)).StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);

        var second = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream") { Content = JsonContent.Create(body) };
        second.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        (await c.SendAsync(second)).StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);

        using var verifyScope = _f.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var receipts = await verifyDb.BunnyWebhookReceipts.CountAsync(r => r.VideoGuid == bunnyVideoId);
        receipts.Should().Be(1);
    }

    [Fact]
    public async Task Webhook_DuplicateRejectedRegression_IsRecordedOnce()
    {
        var bunnyVideoId = "regression-dupe-" + Guid.NewGuid().ToString("N");
        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = Guid.NewGuid(),
                Title = "Regression",
                BunnyLibraryId = 999,
                BunnyVideoId = bunnyVideoId,
                Status = VideoStatus.Ready,
                CreatedByUserId = "admin"
            });
            await db.SaveChangesAsync();
        }

        var c = _f.CreateClient();
        var body = new { videoLibraryId = "999", videoGuid = bunnyVideoId, status = 5 };
        var first = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream") { Content = JsonContent.Create(body) };
        first.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        (await c.SendAsync(first)).StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);

        var second = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream") { Content = JsonContent.Create(body) };
        second.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        (await c.SendAsync(second)).StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);

        using var verifyScope = _f.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var video = await verifyDb.Videos.SingleAsync(v => v.BunnyVideoId == bunnyVideoId);
        video.Status.Should().Be(VideoStatus.Ready);
        var receipts = await verifyDb.BunnyWebhookReceipts.CountAsync(r => r.VideoGuid == bunnyVideoId);
        receipts.Should().Be(1);
    }

    [Fact]
    public async Task Webhook_RetryOfUnprocessedEvent_ReappliesStatusTransition()
    {
        var bunnyVideoId = "retry-video-" + Guid.NewGuid().ToString("N");
        var eventId = "evt-" + Guid.NewGuid().ToString("N");
        var raw = $"{{\"videoLibraryId\":\"999\",\"videoGuid\":\"{bunnyVideoId}\",\"status\":4}}";

        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = Guid.NewGuid(),
                Title = "Retry",
                BunnyLibraryId = 999,
                BunnyVideoId = bunnyVideoId,
                Status = VideoStatus.Processing,
                CreatedByUserId = "admin"
            });
            db.BunnyWebhookReceipts.Add(new BunnyWebhookReceipt
            {
                BodyHash = Sha256(raw),
                SignatureHash = "prior",
                VideoGuid = bunnyVideoId,
                Status = 4,
                ReceivedAt = DateTimeOffset.UtcNow
            });
            db.WebhookEvents.Add(new WebhookEvent
            {
                EventId = eventId,
                VideoGuid = bunnyVideoId,
                Status = 4,
                RawPayload = raw,
                Attempts = 1,
                LastError = "transient failure",
                ReceivedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        var c = _f.CreateClient();
        var retry = new HttpRequestMessage(HttpMethod.Post, "/api/webhooks/bunny/stream")
        {
            Content = new StringContent(raw, Encoding.UTF8, "application/json")
        };
        retry.Headers.Add("X-Bunny-Webhook-Secret", "the-webhook-secret-value");
        retry.Headers.Add("X-BunnyStream-Event-Id", eventId);
        (await c.SendAsync(retry)).StatusCode.Should().Be(System.Net.HttpStatusCode.Accepted);

        using var verifyScope = _f.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var video = await verifyDb.Videos.SingleAsync(v => v.BunnyVideoId == bunnyVideoId);
        video.Status.Should().Be(VideoStatus.Ready);
        var evt = await verifyDb.WebhookEvents.SingleAsync(e => e.EventId == eventId);
        evt.ProcessedAt.Should().NotBeNull();
        evt.Attempts.Should().Be(2);
        evt.LastError.Should().BeNull();
    }

    private static string Sha256(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
}

public class AdversarialEmbedSignatureTests
{
    /// <summary>
    /// Mutating the videoId, expires, or token in a Bunny embed URL must invalidate it.
    /// We can't talk to Bunny, but we can re-derive the SHA256 they will compute
    /// (which is what their playback gate compares against).
    /// </summary>
    [Theory]
    [InlineData("good-video", "good-video-tampered", false)]
    [InlineData("good-video", "good-video", true)]
    public void RecomputingTokenWithMutatedVideoId_FailsToMatch(string original, string mutated, bool shouldMatch)
    {
        const string key = "secret-key";
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();

        string Token(string vid) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key + vid + expires)))
                .ToLowerInvariant();

        var originalToken = Token(original);
        var rederivedToken = Token(mutated);

        (originalToken == rederivedToken).Should().Be(shouldMatch);
    }

    [Fact]
    public void ExpiredEmbedUrl_ProducesDifferentTokenWhenExpiresMutated()
    {
        var opts = new BunnyOptions
        {
            LibraryId = 1,
            EmbedTokenKey = "k",
            ApiKey = "x",
            EmbedBaseUrl = "https://iframe.mediadelivery.net"
        };
        var signer = new BunnyEmbedTokenSigner(Options.Create(opts));
        var url1 = signer.BuildSignedEmbedUrl("v", DateTimeOffset.UtcNow.AddMinutes(5), null, null);
        var url2 = signer.BuildSignedEmbedUrl("v", DateTimeOffset.UtcNow.AddMinutes(15), null, null);

        var t1 = url1.Split("token=")[1].Split('&')[0];
        var t2 = url2.Split("token=")[1].Split('&')[0];
        t1.Should().NotBe(t2);
    }
}

public class RateLimitingTests : IClassFixture<BunnyMockFactory>
{
    private readonly BunnyMockFactory _f;
    public RateLimitingTests(BunnyMockFactory f) => _f = f;

    [Fact]
    public async Task SecurityEvents_RateLimitsAfterBurst()
    {
        var c = _f.CreateClient();
        var any429 = false;
        for (var i = 0; i < 80; i++)
        {
            var resp = await c.PostAsJsonAsync("/api/security/video-events", new { sessionId = (Guid?)null, videoId = (Guid?)null, type = "Other", metadata = (string?)null });
            if ((int)resp.StatusCode == 429) { any429 = true; break; }
        }
        any429.Should().BeTrue("anonymous burst above the per-IP window must be rejected");
    }
}

public class HealthCheckTests : IClassFixture<BunnyMockFactory>
{
    private readonly BunnyMockFactory _f;
    public HealthCheckTests(BunnyMockFactory f) => _f = f;

    [Fact]
    public async Task LivenessProbe_Returns200()
    {
        var c = _f.CreateClient();
        var r = await c.GetAsync("/health/live");
        r.IsSuccessStatusCode.Should().BeTrue();
    }

    [Fact]
    public async Task ReadinessProbe_Returns200()
    {
        var c = _f.CreateClient();
        var r = await c.GetAsync("/health/ready");
        r.IsSuccessStatusCode.Should().BeTrue();
    }

    [Fact]
    public async Task MetricsEndpoint_ReturnsPrometheusText()
    {
        var c = _f.CreateClient();
        var r = await c.GetAsync("/metrics/app");
        r.IsSuccessStatusCode.Should().BeTrue();
        var body = await r.Content.ReadAsStringAsync();
        body.Should().Contain("videosecurity_active_playback_sessions");
        r.Content.Headers.ContentType?.MediaType.Should().Be("text/plain");
    }

    [Fact]
    public async Task CleanupPass_HandlesExpiredSessionsAndOldTelemetryUnderSqlite()
    {
        var videoId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var receiptHash = "old-receipt-" + Guid.NewGuid().ToString("N");

        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Cleanup",
                BunnyLibraryId = 12345,
                BunnyVideoId = "cleanup-" + videoId.ToString("N"),
                Status = VideoStatus.Ready,
                CreatedByUserId = "cleanup-user"
            });
            db.PlaybackSessions.Add(new PlaybackSession
            {
                Id = sessionId,
                UserId = "cleanup-user",
                VideoId = videoId,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-5),
                IpHash = "ip",
                UserAgentHash = "ua",
                WatermarkPayload = "wm"
            });
            db.VideoSecurityEvents.Add(new VideoSecurityEvent
            {
                Id = eventId,
                Type = SecurityEventType.Other,
                VideoId = videoId,
                CreatedAt = DateTimeOffset.UtcNow.AddDays(-120),
                IpHash = "ip",
                UserAgentHash = "ua"
            });
            db.BunnyWebhookReceipts.Add(new BunnyWebhookReceipt
            {
                BodyHash = receiptHash,
                SignatureHash = "sig",
                VideoGuid = "cleanup-" + videoId.ToString("N"),
                Status = 4,
                ReceivedAt = DateTimeOffset.UtcNow.AddDays(-30)
            });
            await db.SaveChangesAsync();
        }

        var cleanup = new ExpiredSessionCleanupService(_f.Services, NullLogger<ExpiredSessionCleanupService>.Instance);
        await cleanup.RunOnceAsync(default);

        using var verifyScope = _f.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var session = await verifyDb.PlaybackSessions.SingleAsync(s => s.Id == sessionId);
        session.Revoked.Should().BeTrue();
        session.RevocationReason.Should().Be("expired");
        (await verifyDb.VideoSecurityEvents.AnyAsync(e => e.Id == eventId)).Should().BeFalse();
        (await verifyDb.BunnyWebhookReceipts.AnyAsync(r => r.BodyHash == receiptHash)).Should().BeFalse();
    }
}
