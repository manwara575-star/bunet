using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Bunny;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Infrastructure.Services;

namespace VideoSecurity.UnitTests;

public class PlaybackSessionServiceTests
{
    private static AppDbContext NewDb()
    {
        var opts = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new AppDbContext(opts);
    }

    private static PlaybackSessionService Build(AppDbContext db, BunnyOptions o, FakeClock clock)
    {
        var ent = new VideoEntitlementService(db, clock);
        var signer = new BunnyEmbedTokenSigner(Options.Create(o));
        var cache = new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions());
        var policies = new VideoSecurityPolicyService(db, cache);
        return new PlaybackSessionService(db, ent, signer, Options.Create(o), clock, policies, VideoSecurity.Infrastructure.Observability.SecurityMetrics.NoOp());
    }

    [Fact]
    public async Task CreateAsync_ReturnsSignedUrlAndPersistsSession()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b1", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v); await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(15) }, new FakeClock());

        var resp = await svc.CreateAsync("u1", v.Id, "1.2.3.4", "ua", default);
        resp.EmbedUrl.Should().Contain("/embed/1/b1?token=");
        resp.SessionId.Should().NotBeEmpty();
        (await db.PlaybackSessions.CountAsync()).Should().Be(1);
        var saved = await db.PlaybackSessions.SingleAsync();
        saved.IpHash.Should().NotBe("1.2.3.4");        // hashed, never stored raw
        saved.UserAgentHash.Should().NotBe("ua");
        resp.Watermark.DisplayText.Should().Contain(saved.Id.ToString("N")[..8]);
    }

    [Fact]
    public async Task CreateAsync_DenialWhenNotEntitled()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b2", CreatedByUserId = "creator", Status = VideoStatus.Ready };
        db.Videos.Add(v); await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk" }, new FakeClock());
        var act = async () => await svc.CreateAsync("notallowed", v.Id, "1", "u", default);
        await act.Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task CreateAsync_FailsWhenVideoNotReady()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b3", CreatedByUserId = "u1", Status = VideoStatus.Processing };
        db.Videos.Add(v); await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk" }, new FakeClock());
        var act = async () => await svc.CreateAsync("u1", v.Id, "1", "u", default);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Heartbeat_RejectsExpiredSession()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b4", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        db.VideoSecurityPolicies.Add(new VideoSecurityPolicy { Tier = VideoSensitivityTier.Standard, EmbedTtlSeconds = 60, AutoRevokeRiskThreshold = 1000 });
        await db.SaveChangesAsync();

        var clock = new FakeClock();
        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(1) }, clock);
        var resp = await svc.CreateAsync("u1", v.Id, "1", "u", default);

        clock.UtcNow = clock.UtcNow.AddMinutes(2);
        var act = async () => await svc.RecordHeartbeatAsync(new(resp.SessionId, 10, true, true), "u1", default);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Heartbeat_RejectsRevoked()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b5", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v); await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(15) }, new FakeClock());
        var resp = await svc.CreateAsync("u1", v.Id, "1", "u", default);
        await svc.RevokeAsync(resp.SessionId, "test", default);

        var act = async () => await svc.RecordHeartbeatAsync(new(resp.SessionId, 1, true, true), "u1", default);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Heartbeat_DifferentUser_Rejected()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b6", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v); await db.SaveChangesAsync();
        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(15) }, new FakeClock());
        var resp = await svc.CreateAsync("u1", v.Id, "1", "u", default);

        var act = async () => await svc.RecordHeartbeatAsync(new(resp.SessionId, 1, true, true), "evil", default);
        await act.Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task Heartbeat_HiddenTab_IncrementsRisk()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "bH", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v); await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(15) }, new FakeClock());
        var resp = await svc.CreateAsync("u1", v.Id, "1", "u", default);

        await svc.RecordHeartbeatAsync(new(resp.SessionId, 5, DocumentVisible: false, DocumentFocused: true), "u1", default);

        var s = await db.PlaybackSessions.SingleAsync();
        s.RiskScore.Should().Be(1);
        s.LastKnownPositionSeconds.Should().Be(5);
    }

    [Fact]
    public async Task Heartbeat_WatermarkRemoved_AddsFifteenAndEmitsEvent()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "bW", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v); await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(15) }, new FakeClock());
        var resp = await svc.CreateAsync("u1", v.Id, "1", "u", default);

        await svc.RecordHeartbeatAsync(new(resp.SessionId, 1, true, true, WatermarkVisible: false), "u1", default);

        var s = await db.PlaybackSessions.SingleAsync();
        s.RiskScore.Should().Be(15);
        (await db.VideoSecurityEvents.AnyAsync(e => e.Type == SecurityEventType.WatermarkTamper)).Should().BeTrue();
    }

    [Fact]
    public async Task ConcurrentSessions_BeyondLimit_RevokesOldest()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "bC", CreatedByUserId = "u1", Status = VideoStatus.Ready, SensitivityTier = VideoSensitivityTier.Premium };
        db.Videos.Add(v);
        db.VideoSecurityPolicies.Add(new VideoSecurityPolicy
        {
            Tier = VideoSensitivityTier.Premium,
            EmbedTtlSeconds = 600,
            MaxConcurrentSessions = 1,
            AutoRevokeRiskThreshold = 1000
        });
        await db.SaveChangesAsync();

        var clock = new FakeClock();
        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(15) }, clock);

        var first = await svc.CreateAsync("u1", v.Id, "1", "u", default);
        clock.UtcNow = clock.UtcNow.AddSeconds(5);
        var second = await svc.CreateAsync("u1", v.Id, "1", "u", default);

        var firstSession = await db.PlaybackSessions.SingleAsync(s => s.Id == first.SessionId);
        firstSession.Revoked.Should().BeTrue();
        firstSession.RevocationReason.Should().Be("ConcurrentSessionLimit");
        firstSession.RevokedAt.Should().NotBeNull();
        (await db.VideoSecurityEvents.CountAsync(e => e.Type == SecurityEventType.ConcurrentSessionLimit)).Should().Be(1);

        var secondSession = await db.PlaybackSessions.SingleAsync(s => s.Id == second.SessionId);
        secondSession.Revoked.Should().BeFalse();
    }

    [Fact]
    public async Task Heartbeat_AutoRevokes_WhenRiskAboveThreshold()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "bR", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        db.VideoSecurityPolicies.Add(new VideoSecurityPolicy
        {
            Tier = VideoSensitivityTier.Standard,
            EmbedTtlSeconds = 900,
            MaxConcurrentSessions = 5,
            RequireWatermark = true,
            AutoRevokeRiskThreshold = 10
        });
        await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk", DefaultSessionTtl = TimeSpan.FromMinutes(15) }, new FakeClock());
        var resp = await svc.CreateAsync("u1", v.Id, "1", "u", default);

        await svc.RecordHeartbeatAsync(new(resp.SessionId, 1, true, true, WatermarkVisible: false), "u1", default);

        var s = await db.PlaybackSessions.SingleAsync();
        s.Revoked.Should().BeTrue();
        s.RevocationReason.Should().Be("RiskAutoRevoke");
        s.RevokedAt.Should().NotBeNull();
        (await db.VideoSecurityEvents.AnyAsync(e => e.Type == SecurityEventType.RiskAutoRevoke)).Should().BeTrue();
    }
}
