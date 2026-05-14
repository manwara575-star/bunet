using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Bunny;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Infrastructure.Services;

namespace VideoSecurity.UnitTests;

public class DeviceFingerprintRiskTests
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
        var cache = new Microsoft.Extensions.Caching.Memory.MemoryCache(
            new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions());
        var policies = new VideoSecurityPolicyService(db, cache);
        return new PlaybackSessionService(db, ent, signer, Options.Create(o), clock, policies,
            VideoSecurity.Infrastructure.Observability.SecurityMetrics.NoOp());
    }

    [Fact]
    public async Task Heartbeat_DeviceFingerprintChange_IncrementsRiskByTen()
    {
        await using var db = NewDb();
        var v = new Video { Title = "fp-test", BunnyVideoId = "bFP", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions
        {
            LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk",
            DefaultSessionTtl = TimeSpan.FromMinutes(15)
        }, new FakeClock());
        var resp = await svc.CreateAsync("u1", v.Id, "1.2.3.4", "ua", default);

        // First heartbeat establishes the fingerprint
        await svc.RecordHeartbeatAsync(
            new HeartbeatRequest(resp.SessionId, 5, true, true, DeviceFingerprint: "device-A"), "u1", default);
        var s1 = await db.PlaybackSessions.SingleAsync();
        s1.DeviceFingerprintHash.Should().NotBeNullOrEmpty();
        s1.RiskScore.Should().Be(0); // first fingerprint just stored, no penalty

        // Second heartbeat with DIFFERENT fingerprint should add +10
        await svc.RecordHeartbeatAsync(
            new HeartbeatRequest(resp.SessionId, 10, true, true, DeviceFingerprint: "device-B"), "u1", default);
        var s2 = await db.PlaybackSessions.SingleAsync();
        s2.RiskScore.Should().Be(10);
    }

    [Fact]
    public async Task Heartbeat_SameDeviceFingerprint_NoRiskIncrease()
    {
        await using var db = NewDb();
        var v = new Video { Title = "fp-same", BunnyVideoId = "bFS", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        await db.SaveChangesAsync();

        var svc = Build(db, new BunnyOptions
        {
            LibraryId = 1, ApiKey = "k", EmbedTokenKey = "kk",
            DefaultSessionTtl = TimeSpan.FromMinutes(15)
        }, new FakeClock());
        var resp = await svc.CreateAsync("u1", v.Id, "1.2.3.4", "ua", default);

        await svc.RecordHeartbeatAsync(
            new HeartbeatRequest(resp.SessionId, 5, true, true, DeviceFingerprint: "device-A"), "u1", default);
        await svc.RecordHeartbeatAsync(
            new HeartbeatRequest(resp.SessionId, 10, true, true, DeviceFingerprint: "device-A"), "u1", default);

        var s = await db.PlaybackSessions.SingleAsync();
        s.RiskScore.Should().Be(0);
    }
}
