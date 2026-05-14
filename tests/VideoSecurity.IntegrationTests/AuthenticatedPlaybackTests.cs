using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web;

namespace VideoSecurity.IntegrationTests;

public sealed class AuthenticatedPlaybackTests : IClassFixture<BunnyMockFactory>
{
    private readonly BunnyMockFactory _f;
    public AuthenticatedPlaybackTests(BunnyMockFactory f) => _f = f;

    [Fact]
    public async Task WatchPageAndPlaybackApis_WorkWithAntiforgery_WithoutInitialUrlLeak()
    {
        await using var factory = _f.WithWebHostBuilder(builder =>
        {
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
        var bunnyVideoId = "bunny-video-" + videoId.ToString("N");
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Protected",
                Description = "Integration path",
                BunnyLibraryId = 12345,
                BunnyVideoId = bunnyVideoId,
                Status = VideoStatus.Ready,
                CreatedByUserId = TestAuthHandler.UserId,
                DurationSeconds = 120
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var watch = await client.GetAsync($"/player/watch/{videoId}");
        watch.EnsureSuccessStatusCode();
        var html = await watch.Content.ReadAsStringAsync();

        html.Should().Contain("name=\"__RequestVerificationToken\"");
        html.IndexOf("name=\"__RequestVerificationToken\"", StringComparison.Ordinal)
            .Should().BeLessThan(html.IndexOf("/js/watch-page.js", StringComparison.Ordinal));
        html.Should().NotContain(".m3u8");
        html.Should().NotContain(".mp4");
        html.Should().NotContain("b-cdn.net");
        html.Should().NotContain($"/embed/12345/{bunnyVideoId}");
        html.Should().NotContain("allowfullscreen");

        var token = ExtractAntiforgeryToken(html);
        var sessionReq = new HttpRequestMessage(HttpMethod.Post, $"/api/videos/{videoId}/playback-session");
        sessionReq.Headers.Add("RequestVerificationToken", token);
        var sessionResp = await client.SendAsync(sessionReq);
        var sessionBody = await sessionResp.Content.ReadAsStringAsync();
        sessionResp.IsSuccessStatusCode.Should().BeTrue(sessionBody);
        var session = await sessionResp.Content.ReadFromJsonAsync<PlaybackSessionResponse>();
        session.Should().NotBeNull();
        session!.EmbedUrl.Should().StartWith($"https://iframe.mediadelivery.net/embed/12345/{bunnyVideoId}?token=");
        session.EmbedUrl.Should().NotContain("sid=");
        session.EmbedUrl.Should().NotContain("b-cdn.net");

        var heartbeat = new HttpRequestMessage(HttpMethod.Post, "/api/videos/heartbeat")
        {
            Content = JsonContent.Create(new
            {
                sessionId = session.SessionId,
                positionSeconds = 15,
                documentVisible = true,
                documentFocused = true
            })
        };
        heartbeat.Headers.Add("RequestVerificationToken", token);
        var hbResp = await client.SendAsync(heartbeat);
        hbResp.StatusCode.Should().Be(System.Net.HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task ProtectedPost_WithoutAntiforgery_IsRejected()
    {
        await using var factory = _f.WithWebHostBuilder(builder =>
        {
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

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
    client.BaseAddress = new Uri("https://localhost");
        var resp = await client.PostAsync($"/api/videos/{Guid.NewGuid()}/playback-session", null);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ActiveGrant_AllowsMeCatalogPlayerAndPlaybackSession_UnderSqlite()
    {
        await using var factory = AuthenticatedFactory();
        var videoId = Guid.NewGuid();
        var bunnyVideoId = "grant-video-" + videoId.ToString("N");
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Granted Video",
                BunnyLibraryId = 12345,
                BunnyVideoId = bunnyVideoId,
                Status = VideoStatus.Ready,
                CreatedByUserId = "creator",
                DurationSeconds = 120
            });
            db.VideoAccessGrants.Add(new VideoAccessGrant
            {
                UserId = TestAuthHandler.UserId,
                VideoId = videoId,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");

        var me = await client.GetStringAsync("/api/me/videos");
        me.Should().Contain(videoId.ToString());

        var catalog = await client.GetStringAsync("/catalog");
        catalog.Should().Contain("Granted Video");
        catalog.Should().NotContain("b-cdn.net");

        var watch = await client.GetAsync($"/player/watch/{videoId}");
        watch.EnsureSuccessStatusCode();
        var html = await watch.Content.ReadAsStringAsync();
        var token = ExtractAntiforgeryToken(html);

        var sessionReq = new HttpRequestMessage(HttpMethod.Post, $"/api/videos/{videoId}/playback-session");
        sessionReq.Headers.Add("RequestVerificationToken", token);
        var sessionResp = await client.SendAsync(sessionReq);
        sessionResp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK, await sessionResp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ExpiredGrant_DoesNotAuthorizeMeCatalogPlayerOrPlaybackSession_UnderSqlite()
    {
        await using var factory = AuthenticatedFactory();
        var videoId = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Expired Grant Video",
                BunnyLibraryId = 12345,
                BunnyVideoId = "expired-grant-" + videoId.ToString("N"),
                Status = VideoStatus.Ready,
                CreatedByUserId = "creator",
                DurationSeconds = 120
            });
            db.VideoAccessGrants.Add(new VideoAccessGrant
            {
                UserId = TestAuthHandler.UserId,
                VideoId = videoId,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1)
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");

        var me = await client.GetStringAsync("/api/me/videos");
        me.Should().NotContain(videoId.ToString());

        var catalog = await client.GetStringAsync("/catalog");
        catalog.Should().NotContain("Expired Grant Video");

        var watch = await client.GetAsync($"/player/watch/{videoId}");
        watch.StatusCode.Should().Be(System.Net.HttpStatusCode.Forbidden);
    }

    private WebApplicationFactory<Program> AuthenticatedFactory() => _f.WithWebHostBuilder(builder =>
    {
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

    private static string ExtractAntiforgeryToken(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"");
        match.Success.Should().BeTrue("watch page should render an antiforgery token");
        return match.Groups["token"].Value;
    }
}

public sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Test";
    public const string UserId = "test-user";

    public TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, UserId),
            new Claim(ClaimTypes.Name, "Test User"),
            new Claim(ClaimTypes.Role, IdentitySeeder.AdminRole)
        };
        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
