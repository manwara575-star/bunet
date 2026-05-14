using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Infrastructure.Services;

namespace VideoSecurity.UnitTests;

public class VideoSecurityPolicyServiceTests
{
    private static AppDbContext NewDb()
    {
        var opts = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new AppDbContext(opts);
    }

    private static VideoSecurityPolicyService Build(AppDbContext db) =>
        new(db, new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public async Task ReturnsPremiumPolicy_ForPremiumTierVideo()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "bp", CreatedByUserId = "u", Status = VideoStatus.Ready, SensitivityTier = VideoSensitivityTier.Premium };
        db.Videos.Add(v);
        db.VideoSecurityPolicies.Add(new VideoSecurityPolicy
        {
            Tier = VideoSensitivityTier.Premium,
            EmbedTtlSeconds = 600,
            HeartbeatIntervalSeconds = 10,
            MaxConcurrentSessions = 1,
            AutoRevokeRiskThreshold = 60
        });
        await db.SaveChangesAsync();

        var svc = Build(db);
        var p = await svc.GetForVideoAsync(v.Id, default);

        p.Tier.Should().Be(VideoSensitivityTier.Premium);
        p.EmbedTtlSeconds.Should().Be(600);
        p.MaxConcurrentSessions.Should().Be(1);
        p.AutoRevokeRiskThreshold.Should().Be(60);
    }

    [Fact]
    public async Task ReturnsDefaults_WhenNoPolicyRowExists()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "bd", CreatedByUserId = "u", Status = VideoStatus.Ready, SensitivityTier = VideoSensitivityTier.Standard };
        db.Videos.Add(v);
        await db.SaveChangesAsync();

        var svc = Build(db);
        var p = await svc.GetForVideoAsync(v.Id, default);

        p.Tier.Should().Be(VideoSensitivityTier.Standard);
        p.EmbedTtlSeconds.Should().Be(900);
        p.HeartbeatIntervalSeconds.Should().Be(15);
        p.MaxConcurrentSessions.Should().Be(2);
        p.AutoRevokeRiskThreshold.Should().Be(80);
    }

    [Fact]
    public async Task ReturnsCriticalDefaults_WhenTierCriticalAndNoRow()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "bc", CreatedByUserId = "u", Status = VideoStatus.Ready, SensitivityTier = VideoSensitivityTier.Critical };
        db.Videos.Add(v);
        await db.SaveChangesAsync();

        var svc = Build(db);
        var p = await svc.GetForVideoAsync(v.Id, default);

        p.Tier.Should().Be(VideoSensitivityTier.Critical);
        p.EmbedTtlSeconds.Should().Be(300);
        p.MaxConcurrentSessions.Should().Be(1);
        p.AutoRevokeRiskThreshold.Should().Be(40);
    }
}
