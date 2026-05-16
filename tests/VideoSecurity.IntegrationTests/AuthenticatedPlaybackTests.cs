using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web;
using VideoSecurity.Web.HostedServices;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

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
        AssertNoDownloadableUrls(html);
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
        AssertNoDownloadableUrls(session.EmbedUrl!);

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
    public async Task SecureWebRtcSession_DoesNotReturnDownloadableMediaUrls_AndRequiresHeartbeatToken()
    {
        await using var factory = AuthenticatedFactory();
        var videoId = Guid.NewGuid();
        string sourcePath;
        using (var scope = factory.Services.CreateScope())
        {
            var storage = scope.ServiceProvider.GetRequiredService<IProtectedMediaStorage>();
            await using var source = new MemoryStream([1, 2, 3, 4]);
            var saved = await storage.SaveSourceAsync(videoId, "secure.mp4", "video/mp4", source, default);
            sourcePath = saved.RelativePath;

            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Secure WebRTC",
                BunnyLibraryId = 0,
                BunnyVideoId = "local-" + videoId.ToString("N"),
                PlaybackProvider = PlaybackProvider.SecureWebRtc,
                ProtectedMediaStatus = ProtectedMediaStatus.SourceUploaded,
                ProtectedSourcePath = sourcePath,
                ProtectedSourceOriginalFileName = saved.OriginalFileName,
                ProtectedSourceContentType = saved.ContentType,
                ProtectedSourceSizeBytes = saved.SizeBytes,
                ProtectedSourceUploadedAt = DateTimeOffset.UtcNow,
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
        html.Should().Contain("id=\"player-video\"");
        AssertNoDownloadableUrls(html);

        var token = ExtractAntiforgeryToken(html);
        var sessionReq = new HttpRequestMessage(HttpMethod.Post, $"/api/videos/{videoId}/playback-session");
        sessionReq.Headers.Add("RequestVerificationToken", token);
        var sessionResp = await client.SendAsync(sessionReq);
        sessionResp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK, await sessionResp.Content.ReadAsStringAsync());
        var sessionBody = await sessionResp.Content.ReadAsStringAsync();
        AssertNoDownloadableUrls(sessionBody);

        var session = await sessionResp.Content.ReadFromJsonAsync<PlaybackSessionResponse>();
        session.Should().NotBeNull();
        session!.PlaybackProvider.Should().Be(nameof(PlaybackProvider.SecureWebRtc));
        session.EmbedUrl.Should().BeNull();
        session.HeartbeatToken.Should().NotBeNullOrWhiteSpace();
        session.SecurePlayback.Should().NotBeNull();
        session.SecurePlayback!.OfferEndpoint.Should().Be($"/api/secure-playback/{session.SessionId}/offer");

        var missingHeartbeatToken = new HttpRequestMessage(HttpMethod.Post, "/api/videos/heartbeat")
        {
            Content = JsonContent.Create(new
            {
                sessionId = session.SessionId,
                positionSeconds = 1,
                documentVisible = true,
                documentFocused = true
            })
        };
        missingHeartbeatToken.Headers.Add("RequestVerificationToken", token);
        var missingHeartbeatResp = await client.SendAsync(missingHeartbeatToken);
        missingHeartbeatResp.StatusCode.Should().Be(System.Net.HttpStatusCode.Forbidden);

        var heartbeat = new HttpRequestMessage(HttpMethod.Post, "/api/videos/heartbeat")
        {
            Content = JsonContent.Create(new
            {
                sessionId = session.SessionId,
                positionSeconds = 2,
                documentVisible = true,
                documentFocused = true,
                heartbeatToken = session.HeartbeatToken
            })
        };
        heartbeat.Headers.Add("RequestVerificationToken", token);
        var hbResp = await client.SendAsync(heartbeat);
        hbResp.StatusCode.Should().Be(System.Net.HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task SecureWebRtcSession_FailsClosed_WhenWorkerIsNotConfigured()
    {
        await using var factory = AuthenticatedFactory(configureSecurePlayback: false);
        var videoId = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var storage = scope.ServiceProvider.GetRequiredService<IProtectedMediaStorage>();
            await using var source = new MemoryStream([1, 2, 3, 4]);
            var saved = await storage.SaveSourceAsync(videoId, "secure.mp4", "video/mp4", source, default);

            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Secure WebRTC",
                BunnyLibraryId = 0,
                BunnyVideoId = "local-" + videoId.ToString("N"),
                PlaybackProvider = PlaybackProvider.SecureWebRtc,
                ProtectedMediaStatus = ProtectedMediaStatus.SourceUploaded,
                ProtectedSourcePath = saved.RelativePath,
                Status = VideoStatus.Ready,
                CreatedByUserId = TestAuthHandler.UserId
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var html = await client.GetStringAsync($"/player/watch/{videoId}");
        var token = ExtractAntiforgeryToken(html);

        var sessionReq = new HttpRequestMessage(HttpMethod.Post, $"/api/videos/{videoId}/playback-session");
        sessionReq.Headers.Add("RequestVerificationToken", token);
        var resp = await client.SendAsync(sessionReq);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Conflict);
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("Secure WebRTC playback is not configured");
        AssertNoDownloadableUrls(body);
    }

    [Fact]
    public async Task SecureWebRtcOffer_RejectsMissingToken()
    {
        await using var factory = AuthenticatedFactory();
        var (client, token, session) = await CreateSecureWebRtcSessionAsync(factory);

        var offer = CreateOfferRequest(session.SecurePlayback!.OfferEndpoint, token);
        var resp = await client.SendAsync(offer);

        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task SecureWebRtcOffer_RejectsWrongUser()
    {
        await using var factory = AuthenticatedFactory();
        var (client, token, session) = await CreateSecureWebRtcSessionAsync(factory);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await db.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
            stored.UserId = "other-user";
            await db.SaveChangesAsync();
        }

        var offer = CreateOfferRequest(session.SecurePlayback!.OfferEndpoint, token, session.HeartbeatToken);
        var resp = await client.SendAsync(offer);

        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task SecureWebRtcOffer_RejectsExpiredSession()
    {
        await using var factory = AuthenticatedFactory();
        var (client, token, session) = await CreateSecureWebRtcSessionAsync(factory);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await db.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
            stored.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        var offer = CreateOfferRequest(session.SecurePlayback!.OfferEndpoint, token, session.HeartbeatToken);
        var resp = await client.SendAsync(offer);

        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Conflict);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("expired");
    }

    [Fact]
    public async Task SecureWebRtcOffer_RejectsRevokedSession()
    {
        await using var factory = AuthenticatedFactory();
        var (client, token, session) = await CreateSecureWebRtcSessionAsync(factory);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await db.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
            stored.Revoked = true;
            stored.RevokedAt = DateTimeOffset.UtcNow;
            stored.RevocationReason = "test";
            await db.SaveChangesAsync();
        }

        var offer = CreateOfferRequest(session.SecurePlayback!.OfferEndpoint, token, session.HeartbeatToken);
        var resp = await client.SendAsync(offer);

        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Conflict);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("revoked");
    }

    [Fact]
    public async Task SecureWebRtcOffer_RejectsInvalidProtectedSourcePath()
    {
        await using var factory = AuthenticatedFactory();
        var (client, token, session) = await CreateSecureWebRtcSessionAsync(factory);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await db.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
            var video = await db.Videos.SingleAsync(v => v.Id == stored.VideoId);
            video.ProtectedSourcePath = Path.Combine("..", "escape.mp4");
            await db.SaveChangesAsync();
        }

        var offer = CreateOfferRequest(session.SecurePlayback!.OfferEndpoint, token, session.HeartbeatToken);
        var resp = await client.SendAsync(offer);

        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.Conflict);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("invalid");
    }

    [Fact]
    public async Task SecureWebRtcOffer_ProxiesWhepAnswer_WhenWorkerAccepts()
    {
        await using var factory = AuthenticatedFactory();
        var (client, token, session) = await CreateSecureWebRtcSessionAsync(factory);
        var answerSdp = "v=0\r\ns=secure-answer\r\n";
        _f.Bunny
            .Given(Request.Create().WithPath($"/whep/{session.SessionId:N}").UsingPost())
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/sdp")
                .WithBody(answerSdp));

        var offer = CreateOfferRequest(session.SecurePlayback!.OfferEndpoint, token, session.HeartbeatToken);
        var resp = await client.SendAsync(offer);
        var body = await resp.Content.ReadAsStringAsync();

        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK, body);
        AssertNoDownloadableUrls(body);
        var result = JsonSerializer.Deserialize<SecurePlaybackAnswerResponse>(body, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        result.Should().NotBeNull();
        result!.Type.Should().Be("answer");
        result.Sdp.Should().Be(answerSdp);
    }

    [Fact]
    public async Task SecureWebRtcPublicDemo_ProxiesOfferWithoutLoginOrAntiforgery()
    {
        await using var factory = _f.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, cfg) =>
            {
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecurePlayback:Enabled"] = "true",
                    ["SecurePlayback:WhepEndpointTemplate"] = $"{_f.Bunny.Url}/public-whep/{{sessionId}}",
                    ["SecurePlayback:StartFfmpegOnSessionCreate"] = "false",
                    ["SecurePlayback:BurnWatermark"] = "true"
                });
            });
        });

        var videoId = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var storage = scope.ServiceProvider.GetRequiredService<IProtectedMediaStorage>();
            await using var source = new MemoryStream([1, 2, 3, 4]);
            var saved = await storage.SaveSourceAsync(videoId, "secure.mp4", "video/mp4", source, default);

            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Public Secure WebRTC",
                BunnyLibraryId = 0,
                BunnyVideoId = "local-" + videoId.ToString("N"),
                PlaybackProvider = PlaybackProvider.SecureWebRtc,
                ProtectedMediaStatus = ProtectedMediaStatus.SourceUploaded,
                ProtectedSourcePath = saved.RelativePath,
                Status = VideoStatus.Ready,
                AllowPublicDemo = true,
                CreatedByUserId = TestAuthHandler.UserId
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var demo = await client.GetAsync($"/demo/{videoId}");
        demo.StatusCode.Should().Be(System.Net.HttpStatusCode.OK);
        var html = await demo.Content.ReadAsStringAsync();
        var bootstrapId = Regex.Match(html, "/public-playback/bootstrap/(?<id>[^\"]+)").Groups["id"].Value;
        bootstrapId.Should().NotBeNullOrWhiteSpace();

        var sessionResp = await client.PostAsync($"/public-playback/bootstrap/{bootstrapId}", null);
        sessionResp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK, await sessionResp.Content.ReadAsStringAsync());
        var session = await sessionResp.Content.ReadFromJsonAsync<PlaybackSessionResponse>();
        session.Should().NotBeNull();
        session!.PlaybackProvider.Should().Be(nameof(PlaybackProvider.SecureWebRtc));
        session.HeartbeatToken.Should().NotBeNullOrWhiteSpace();
        session.EmbedUrl.Should().BeNull();

        var answerSdp = "v=0\r\ns=public-secure-answer\r\n";
        _f.Bunny
            .Given(Request.Create().WithPath($"/public-whep/{session.SessionId:N}").UsingPost())
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/sdp")
                .WithBody(answerSdp));

        var offer = new HttpRequestMessage(HttpMethod.Post, session.SecurePlayback!.OfferEndpoint)
        {
            Content = JsonContent.Create(new { type = "offer", sdp = "v=0\r\n" })
        };
        offer.Headers.Add("X-Playback-Session-Token", session.HeartbeatToken!);

        var offerResp = await client.SendAsync(offer);
        var body = await offerResp.Content.ReadAsStringAsync();
        offerResp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK, body);
        AssertNoDownloadableUrls(body);
        body.Should().Contain("public-secure-answer");
    }

    [Fact]
    public async Task SecureWebRtcHeartbeatRiskRevocation_StopsWorker()
    {
        await using var factory = AuthenticatedFactory(useRecordingWorker: true);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var policy = await db.VideoSecurityPolicies.SingleOrDefaultAsync(p => p.Tier == VideoSensitivityTier.Standard);
            if (policy is null)
            {
                db.VideoSecurityPolicies.Add(new VideoSecurityPolicy
                {
                    Tier = VideoSensitivityTier.Standard,
                    RequireWatermark = true,
                    AutoRevokeRiskThreshold = 10
                });
            }
            else
            {
                policy.RequireWatermark = true;
                policy.AutoRevokeRiskThreshold = 10;
            }
            await db.SaveChangesAsync();
        }

        var (client, token, session) = await CreateSecureWebRtcSessionAsync(factory);
        var worker = factory.Services.GetRequiredService<RecordingSecureMediaWorker>();
        worker.StartedSessions.Should().Contain(session.SessionId);

        var heartbeat = new HttpRequestMessage(HttpMethod.Post, "/api/videos/heartbeat")
        {
            Content = JsonContent.Create(new
            {
                sessionId = session.SessionId,
                positionSeconds = 3,
                documentVisible = true,
                documentFocused = true,
                watermarkVisible = false,
                heartbeatToken = session.HeartbeatToken
            })
        };
        heartbeat.Headers.Add("RequestVerificationToken", token);
        var hbResp = await client.SendAsync(heartbeat);
        hbResp.StatusCode.Should().Be(System.Net.HttpStatusCode.NoContent);

        worker.StoppedSessions.Should().Contain(session.SessionId);
        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await verifyDb.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
        stored.Revoked.Should().BeTrue();
        stored.RevocationReason.Should().Be("RiskAutoRevoke");
    }

    [Fact]
    public async Task SecureWebRtcSeek_RepositionsWorkerWithoutRawUrls()
    {
        await using var factory = AuthenticatedFactory(useRecordingWorker: true);
        var (client, _, session) = await CreateSecureWebRtcSessionAsync(factory);
        var worker = factory.Services.GetRequiredService<RecordingSecureMediaWorker>();

        var seek = new HttpRequestMessage(HttpMethod.Post, $"/api/secure-playback/{session.SessionId}/seek")
        {
            Content = JsonContent.Create(new
            {
                positionSeconds = 12.5,
                heartbeatToken = session.HeartbeatToken
            })
        };
        seek.Headers.Add("X-Playback-Session-Token", session.HeartbeatToken!);

        var seekResp = await client.SendAsync(seek);
        var body = await seekResp.Content.ReadAsStringAsync();
        seekResp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK, body);
        AssertNoDownloadableUrls(body);
        body.Should().Contain($"/api/secure-playback/{session.SessionId}/offer");
        worker.SeekRequests.Should().Contain(r =>
            r.SessionId == session.SessionId &&
            Math.Abs(r.Position.TotalSeconds - 12.5) < 0.01);

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await verifyDb.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
        stored.LastKnownPositionSeconds.Should().BeApproximately(12.5, 0.01);
        stored.Revoked.Should().BeFalse();
    }

    [Fact]
    public async Task SecureWebRtcClose_RevokesSessionAndStopsWorker()
    {
        await using var factory = AuthenticatedFactory(useRecordingWorker: true);
        var (client, _, session) = await CreateSecureWebRtcSessionAsync(factory);
        var worker = factory.Services.GetRequiredService<RecordingSecureMediaWorker>();

        var close = new HttpRequestMessage(HttpMethod.Post, $"/api/secure-playback/{session.SessionId}/close")
        {
            Content = JsonContent.Create(new { heartbeatToken = session.HeartbeatToken })
        };
        close.Headers.Add("X-Playback-Session-Token", session.HeartbeatToken!);

        var closeResp = await client.SendAsync(close);
        closeResp.StatusCode.Should().Be(System.Net.HttpStatusCode.NoContent);
        worker.StoppedSessions.Should().Contain(session.SessionId);

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await verifyDb.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
        stored.Revoked.Should().BeTrue();
        stored.RevocationReason.Should().Be("ClientClosed");
    }

    [Fact]
    public async Task SecureWebRtcStaleHeartbeatCleanup_RevokesSessionAndStopsWorker()
    {
        await using var factory = AuthenticatedFactory(useRecordingWorker: true);
        var (_, _, session) = await CreateSecureWebRtcSessionAsync(factory);
        var worker = factory.Services.GetRequiredService<RecordingSecureMediaWorker>();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await db.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
            stored.CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-2);
            stored.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10);
            stored.LastHeartbeatAt = null;
            await db.SaveChangesAsync();
        }

        var cleanup = new ExpiredSessionCleanupService(
            factory.Services,
            factory.Services.GetRequiredService<ILogger<ExpiredSessionCleanupService>>());
        await cleanup.RunOnceAsync(CancellationToken.None);

        worker.StoppedSessions.Should().Contain(session.SessionId);
        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var verified = await verifyDb.PlaybackSessions.SingleAsync(s => s.Id == session.SessionId);
        verified.Revoked.Should().BeTrue();
        verified.RevocationReason.Should().Be("stale-heartbeat");
        verified.RevokedAt.Should().NotBeNull();
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

    private WebApplicationFactory<Program> AuthenticatedFactory(
        bool configureSecurePlayback = true,
        bool useRecordingWorker = false) => _f.WithWebHostBuilder(builder =>
    {
        builder.ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SecurePlayback:Enabled"] = configureSecurePlayback ? "true" : "false",
                ["SecurePlayback:WhepEndpointTemplate"] = configureSecurePlayback ? $"{_f.Bunny.Url}/whep/{{sessionId}}" : "",
                ["SecurePlayback:StartFfmpegOnSessionCreate"] = "false",
                ["SecurePlayback:BurnWatermark"] = "true",
                ["SecurePlayback:StaleSessionTimeout"] = "00:00:05"
            });
        });
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

            if (useRecordingWorker)
            {
                services.RemoveAll<ISecureMediaWorker>();
                services.AddSingleton<RecordingSecureMediaWorker>();
                services.AddSingleton<ISecureMediaWorker>(sp => sp.GetRequiredService<RecordingSecureMediaWorker>());
            }
        });
    });

    private static async Task<(HttpClient Client, string AntiforgeryToken, PlaybackSessionResponse Session)> CreateSecureWebRtcSessionAsync(
        WebApplicationFactory<Program> factory)
    {
        var videoId = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var storage = scope.ServiceProvider.GetRequiredService<IProtectedMediaStorage>();
            await using var source = new MemoryStream([1, 2, 3, 4]);
            var saved = await storage.SaveSourceAsync(videoId, "secure.mp4", "video/mp4", source, default);

            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Videos.Add(new Video
            {
                Id = videoId,
                Title = "Secure WebRTC",
                BunnyLibraryId = 0,
                BunnyVideoId = "local-" + videoId.ToString("N"),
                PlaybackProvider = PlaybackProvider.SecureWebRtc,
                ProtectedMediaStatus = ProtectedMediaStatus.SourceUploaded,
                ProtectedSourcePath = saved.RelativePath,
                ProtectedSourceOriginalFileName = saved.OriginalFileName,
                ProtectedSourceContentType = saved.ContentType,
                ProtectedSourceSizeBytes = saved.SizeBytes,
                ProtectedSourceUploadedAt = DateTimeOffset.UtcNow,
                Status = VideoStatus.Ready,
                CreatedByUserId = TestAuthHandler.UserId
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var html = await client.GetStringAsync($"/player/watch/{videoId}");
        var token = ExtractAntiforgeryToken(html);

        var sessionReq = new HttpRequestMessage(HttpMethod.Post, $"/api/videos/{videoId}/playback-session");
        sessionReq.Headers.Add("RequestVerificationToken", token);
        var sessionResp = await client.SendAsync(sessionReq);
        sessionResp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK, await sessionResp.Content.ReadAsStringAsync());
        var session = await sessionResp.Content.ReadFromJsonAsync<PlaybackSessionResponse>();
        session.Should().NotBeNull();
        session!.SecurePlayback.Should().NotBeNull();

        return (client, token, session);
    }

    private static HttpRequestMessage CreateOfferRequest(string endpoint, string antiForgeryToken, string? playbackToken = null)
    {
        var offer = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(new { type = "offer", sdp = "v=0\r\n" })
        };
        offer.Headers.Add("RequestVerificationToken", antiForgeryToken);
        if (!string.IsNullOrWhiteSpace(playbackToken))
            offer.Headers.Add("X-Playback-Session-Token", playbackToken);
        return offer;
    }

    private static void AssertNoDownloadableUrls(string body)
    {
        body.Should().NotContain(".m3u8");
        body.Should().NotContain(".mpd");
        body.Should().NotContain(".ts");
        body.Should().NotContain(".m4s");
        body.Should().NotContain(".mp4");
        body.Should().NotContain("b-cdn", "Bunny CDN hosts must not be exposed in this response");
    }

    private static string ExtractAntiforgeryToken(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"");
        match.Success.Should().BeTrue("watch page should render an antiforgery token");
        return match.Groups["token"].Value;
    }
}

public sealed class RecordingSecureMediaWorker : ISecureMediaWorker
{
    public ConcurrentBag<Guid> StartedSessions { get; } = [];
    public ConcurrentBag<Guid> StoppedSessions { get; } = [];
    public ConcurrentBag<SeekRecord> SeekRequests { get; } = [];

    public Task StartAsync(PlaybackSession session, Video video, CancellationToken ct)
    {
        StartedSessions.Add(session.Id);
        return Task.CompletedTask;
    }

    public Task SeekAsync(PlaybackSession session, Video video, TimeSpan position, CancellationToken ct)
    {
        SeekRequests.Add(new SeekRecord(session.Id, position));
        return Task.CompletedTask;
    }

    public Task StopAsync(Guid sessionId, CancellationToken ct)
    {
        StoppedSessions.Add(sessionId);
        return Task.CompletedTask;
    }
}

public sealed record SeekRecord(Guid SessionId, TimeSpan Position);

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
