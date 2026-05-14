using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.IntegrationTests;

public sealed class AdminRevocationTests : IClassFixture<BunnyMockFactory>
{
    private readonly BunnyMockFactory _f;
    public AdminRevocationTests(BunnyMockFactory f) => _f = f;

    [Fact]
    public async Task RevokeSessions_AnonymousReturns401Or302()
    {
        var c = _f.CreateClient(new() { AllowAutoRedirect = false });
        var resp = await c.PostAsync($"/api/admin/videos/{Guid.NewGuid()}/revoke-sessions", null);
        ((int)resp.StatusCode).Should().BeOneOf(401, 302);
    }

    [Fact]
    public async Task RevokeUserAccess_AnonymousReturns401Or302()
    {
        var c = _f.CreateClient(new() { AllowAutoRedirect = false });
        var resp = await c.PostAsJsonAsync($"/api/admin/users/some-user/revoke-video-access", new { });
        ((int)resp.StatusCode).Should().BeOneOf(401, 302);
    }

    [Fact]
    public async Task Admin_CanRevokeAllSessionsForVideo_AndCountIsReturned()
    {
        await using var factory = _f.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureTestServices(services =>
            {
                services.AddAuthentication(TestAuthHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
                services.Configure<AuthenticationOptions>(o =>
                {
                    o.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                    o.DefaultChallengeScheme = TestAuthHandler.SchemeName;
                    o.DefaultScheme = TestAuthHandler.SchemeName;
                });
            });
        });

        var videoId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "RevokeTest",
                BunnyLibraryId = 12345,
                BunnyVideoId = "bunny-" + videoId.ToString("N"),
                Status = VideoStatus.Ready,
                CreatedByUserId = TestAuthHandler.UserId,
                DurationSeconds = 60
            });
            db.PlaybackSessions.AddRange(
                new PlaybackSession
                {
                    Id = Guid.NewGuid(),
                    UserId = TestAuthHandler.UserId,
                    VideoId = videoId,
                    CreatedAt = now,
                    ExpiresAt = now.AddMinutes(30),
                    IpHash = "h", UserAgentHash = "h",
                    WatermarkPayload = "wm"
                },
                new PlaybackSession
                {
                    Id = Guid.NewGuid(),
                    UserId = "another-user",
                    VideoId = videoId,
                    CreatedAt = now,
                    ExpiresAt = now.AddMinutes(30),
                    IpHash = "h", UserAgentHash = "h",
                    WatermarkPayload = "wm"
                },
                new PlaybackSession
                {
                    Id = Guid.NewGuid(),
                    UserId = TestAuthHandler.UserId,
                    VideoId = videoId,
                    CreatedAt = now.AddMinutes(-60),
                    ExpiresAt = now.AddMinutes(-1), // expired -> not counted
                    IpHash = "h", UserAgentHash = "h",
                    WatermarkPayload = "wm"
                });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var token = await GetAntiforgeryTokenAsync(client);
        var req = new HttpRequestMessage(HttpMethod.Post, $"/api/admin/videos/{videoId}/revoke-sessions");
        req.Headers.Add("RequestVerificationToken", token);
        var resp = await client.SendAsync(req);
        var respBody = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, respBody);
        var body = await resp.Content.ReadFromJsonAsync<RevokeCountDto>();
        body.Should().NotBeNull();
        body!.RevokedCount.Should().Be(2);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            // SQLite cannot translate DateTimeOffset comparisons; client-evaluate ExpiresAt.
            var nowCheck = DateTimeOffset.UtcNow;
            var sessions = await db.PlaybackSessions.Where(s => s.VideoId == videoId && !s.Revoked).ToListAsync();
            var remainingActive = sessions.Count(s => s.ExpiresAt > nowCheck);
            remainingActive.Should().Be(0);

            var auditCount = await db.AuditLogs.CountAsync(a => a.Action == AuditAction.SessionRevoked && a.EntityId == videoId.ToString());
            auditCount.Should().BeGreaterOrEqualTo(1);
        }
    }

    [Fact]
    public async Task Admin_CanRevokeUserAccess_GlobalAndScoped()
    {
        await using var factory = _f.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureTestServices(services =>
            {
                services.AddAuthentication(TestAuthHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
                services.Configure<AuthenticationOptions>(o =>
                {
                    o.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                    o.DefaultChallengeScheme = TestAuthHandler.SchemeName;
                    o.DefaultScheme = TestAuthHandler.SchemeName;
                });
            });
        });

        var targetUser = "target-" + Guid.NewGuid().ToString("N");
        var otherUser = "other-" + Guid.NewGuid().ToString("N");
        var videoA = Guid.NewGuid();
        var videoB = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.VideoAccessGrants.AddRange(
                new VideoAccessGrant { UserId = targetUser, VideoId = videoA },
                new VideoAccessGrant { UserId = targetUser, VideoId = videoB },
                new VideoAccessGrant { UserId = otherUser, VideoId = videoA });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var token = await GetAntiforgeryTokenAsync(client);

        // Scoped revoke: only videoA
        var scopedReq = new HttpRequestMessage(HttpMethod.Post, $"/api/admin/users/{targetUser}/revoke-video-access")
        {
            Content = JsonContent.Create(new { videoId = videoA })
        };
        scopedReq.Headers.Add("RequestVerificationToken", token);
        var scopedResp = await client.SendAsync(scopedReq);
        scopedResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var scopedBody = await scopedResp.Content.ReadFromJsonAsync<RevokeCountDto>();
        scopedBody!.RevokedCount.Should().Be(1);

        // Global revoke: remaining active grant for target user (videoB)
        var globalReq = new HttpRequestMessage(HttpMethod.Post, $"/api/admin/users/{targetUser}/revoke-video-access")
        {
            Content = JsonContent.Create(new { })
        };
        globalReq.Headers.Add("RequestVerificationToken", token);
        var globalResp = await client.SendAsync(globalReq);
        globalResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var globalBody = await globalResp.Content.ReadFromJsonAsync<RevokeCountDto>();
        globalBody!.RevokedCount.Should().Be(1);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stillActiveForTarget = await db.VideoAccessGrants.CountAsync(g => g.UserId == targetUser && !g.Revoked);
            stillActiveForTarget.Should().Be(0);

            // Other user's grant must be untouched.
            var otherActive = await db.VideoAccessGrants.CountAsync(g => g.UserId == otherUser && !g.Revoked);
            otherActive.Should().Be(1);

            var audits = await db.AuditLogs.CountAsync(a => a.Action == AuditAction.AccessRevoked && a.EntityId == targetUser);
            audits.Should().BeGreaterOrEqualTo(2);
        }
    }

    private sealed record RevokeCountDto(int RevokedCount);

    // Pulls the antiforgery token off the /admin page (TestAuthHandler authenticates as Admin role).
    private static async Task<string> GetAntiforgeryTokenAsync(HttpClient client)
    {
        var page = await client.GetAsync("/admin");
        page.EnsureSuccessStatusCode();
        var html = await page.Content.ReadAsStringAsync();
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"");
        match.Success.Should().BeTrue("admin page must render an antiforgery token for tests");
        return match.Groups["token"].Value;
    }
}
