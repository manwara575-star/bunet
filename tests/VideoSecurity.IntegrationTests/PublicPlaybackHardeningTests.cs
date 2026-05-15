using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.IntegrationTests;

public sealed class PublicPlaybackHardeningTests
{
    [Fact]
    public async Task Demo_RequiresExplicitPublicDemoApproval()
    {
        var factory = await CreateFactoryAsync();
        try
        {
            var videoId = await SeedVideoAsync(factory, allowPublicDemo: false);
            var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            client.BaseAddress = new Uri("https://localhost");

            var resp = await client.GetAsync($"/demo/{videoId}");

            resp.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }
        finally
        {
            await factory.DisposeAsync();
        }
    }

    [Fact]
    public async Task Demo_RenderedHtml_DoesNotLeakSignedBunnyUrl()
    {
        var factory = await CreateFactoryAsync();
        try
        {
            var videoId = await SeedVideoAsync(factory, allowPublicDemo: true);
            var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            client.BaseAddress = new Uri("https://localhost");

            var resp = await client.GetAsync($"/demo/{videoId}");
            resp.StatusCode.Should().Be(HttpStatusCode.OK);
            resp.Headers.CacheControl?.NoStore.Should().BeTrue();
            Header(resp, "Referrer-Policy").Should().Be("no-referrer");
            var html = await resp.Content.ReadAsStringAsync();

            html.Should().Contain("data-session-endpoint=\"/public-playback/bootstrap/");
            AssertNoRenderedPlaybackLeak(html);
        }
        finally
        {
            await factory.DisposeAsync();
        }
    }

    [Fact]
    public async Task Embed_RejectsPermanentLinks_AndRenderedHtmlDoesNotLeakSignedBunnyUrl()
    {
        var factory = await CreateFactoryAsync();
        try
        {
            var videoId = await SeedVideoAsync(factory, allowPublicDemo: true);
            var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            client.BaseAddress = new Uri("https://localhost");

            var permanent = ComputeEmbedToken(videoId, expires: 0);
            var permanentResp = await client.GetAsync($"/embed/{videoId}?token={permanent}&expires=0");
            permanentResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);

            var expires = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds();
            var token = ComputeEmbedToken(videoId, expires);
            var resp = await client.GetAsync($"/embed/{videoId}?token={token}&expires={expires}");
            resp.StatusCode.Should().Be(HttpStatusCode.OK);
            resp.Headers.CacheControl?.NoStore.Should().BeTrue();
            Header(resp, "Referrer-Policy").Should().Be("no-referrer");
            var html = await resp.Content.ReadAsStringAsync();

            html.Should().Contain("data-session-endpoint=\"/public-playback/bootstrap/");
            AssertNoRenderedPlaybackLeak(html);
        }
        finally
        {
            await factory.DisposeAsync();
        }
    }

    [Fact]
    public async Task PublicBootstrap_IsOneTime_AndHeartbeatRequiresNonce()
    {
        var factory = await CreateFactoryAsync();
        try
        {
            var videoId = await SeedVideoAsync(factory, allowPublicDemo: true);
            var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            client.BaseAddress = new Uri("https://localhost");

            var html = await client.GetStringAsync($"/demo/{videoId}");
            var endpoint = ExtractSessionEndpoint(html);

            var bootstrapResp = await client.PostAsync(endpoint, null);
            bootstrapResp.StatusCode.Should().Be(HttpStatusCode.OK, await bootstrapResp.Content.ReadAsStringAsync());
            var session = await bootstrapResp.Content.ReadFromJsonAsync<PlaybackSessionResponse>();
            session.Should().NotBeNull();
            session!.EmbedUrl.Should().StartWith("https://iframe.mediadelivery.net/embed/");
            session.HeartbeatToken.Should().NotBeNullOrWhiteSpace();

            var replayResp = await client.PostAsync(endpoint, null);
            replayResp.StatusCode.Should().Be(HttpStatusCode.Gone);

            var missingNonce = await client.PostAsJsonAsync("/embed/heartbeat", new
            {
                sessionId = session.SessionId,
                positionSeconds = 5,
                documentVisible = true,
                documentFocused = true,
                watermarkVisible = true,
                fullscreen = false
            });
            missingNonce.StatusCode.Should().Be(HttpStatusCode.Forbidden);

            var okHeartbeat = await client.PostAsJsonAsync("/embed/heartbeat", new
            {
                sessionId = session.SessionId,
                positionSeconds = 10,
                documentVisible = true,
                documentFocused = true,
                watermarkVisible = true,
                fullscreen = false,
                heartbeatToken = session.HeartbeatToken
            });
            okHeartbeat.StatusCode.Should().Be(HttpStatusCode.NoContent);
        }
        finally
        {
            await factory.DisposeAsync();
        }
    }

    private static async Task<BunnyMockFactory> CreateFactoryAsync()
    {
        var factory = new BunnyMockFactory();
        await factory.InitializeAsync();
        return factory;
    }

    private static async Task<Guid> SeedVideoAsync(BunnyMockFactory factory, bool allowPublicDemo)
    {
        var videoId = Guid.NewGuid();
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Videos.Add(new Video
        {
            Id = videoId,
            Title = "Public hardening test",
            BunnyLibraryId = 12345,
            BunnyVideoId = "public-hardening-" + videoId.ToString("N"),
            Status = VideoStatus.Ready,
            CreatedByUserId = "test",
            DurationSeconds = 120,
            AllowPublicDemo = allowPublicDemo
        });
        await db.SaveChangesAsync();
        return videoId;
    }

    private static void AssertNoRenderedPlaybackLeak(string html)
    {
        html.Should().NotContain("iframe.mediadelivery.net");
        html.Should().NotContain("token=");
        html.Should().NotContain("embedUrl");
        html.Should().NotContain(".m3u8");
        html.Should().NotContain(".mpd");
        html.Should().NotContain(".mp4");
        html.Should().NotContain("b-cdn.net");
    }

    private static string ExtractSessionEndpoint(string html)
    {
        var match = Regex.Match(html, "data-session-endpoint=\"([^\"]+)\"");
        match.Success.Should().BeTrue("public playback pages should expose only an opaque bootstrap endpoint");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    private static string Header(HttpResponseMessage resp, string name) =>
        resp.Headers.TryGetValues(name, out var values) ? values.Single() : string.Empty;

    private static string ComputeEmbedToken(Guid videoId, long expires)
    {
        const string key = "integration-embed-key-for-tests-only-32";
        var raw = key + "|embed|" + videoId + "|" + expires;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
    }
}
