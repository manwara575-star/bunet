using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Infrastructure.Services;

namespace VideoSecurity.UnitTests;

public sealed class SecurityEventServiceTests
{
    [Fact]
    public async Task RecordAsync_DoesNotApplyRiskToAnotherUsersSession()
    {
        var opts = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        await using var db = new AppDbContext(opts);

        var video = new Video
        {
            Id = Guid.NewGuid(),
            Title = "Protected",
            BunnyVideoId = "bunny-video",
            CreatedByUserId = "victim",
            Status = VideoStatus.Ready
        };
        var session = new PlaybackSession
        {
            Id = Guid.NewGuid(),
            UserId = "victim",
            VideoId = video.Id,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
            IpHash = "ip",
            UserAgentHash = "ua"
        };
        db.Videos.Add(video);
        db.PlaybackSessions.Add(session);
        await db.SaveChangesAsync();

        var clock = new FakeClock();
        var policyService = new VideoSecurityPolicyService(db, new MemoryCache(new MemoryCacheOptions()));
        var service = new SecurityEventService(
            db,
            clock,
            Options.Create(new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "ek", CdnHostname = "cdn" }),
            policyService,
            VideoSecurity.Infrastructure.Observability.SecurityMetrics.NoOp());

        await service.RecordAsync(new SecurityEventRequest(session.Id, video.Id, "WatermarkTamper", null), "attacker", "1.2.3.4", "ua", default);

        var reloaded = await db.PlaybackSessions.SingleAsync(s => s.Id == session.Id);
        reloaded.RiskScore.Should().Be(0);
        reloaded.Revoked.Should().BeFalse();
        (await db.VideoSecurityEvents.CountAsync()).Should().Be(1);
    }
}
