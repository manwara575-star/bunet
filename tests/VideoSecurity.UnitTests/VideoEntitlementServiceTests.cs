using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Infrastructure.Services;

namespace VideoSecurity.UnitTests;

public class VideoEntitlementServiceTests
{
    private static AppDbContext NewDb()
    {
        var opts = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new AppDbContext(opts);
    }

    [Fact]
    public async Task DeniesAnonymous()
    {
        await using var db = NewDb();
        var svc = new VideoEntitlementService(db, new FakeClock());
        (await svc.IsAuthorizedAsync("", Guid.NewGuid(), default)).Should().BeFalse();
    }

    [Fact]
    public async Task AllowsCreator()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b1", CreatedByUserId = "u1", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        await db.SaveChangesAsync();

        var svc = new VideoEntitlementService(db, new FakeClock());
        (await svc.IsAuthorizedAsync("u1", v.Id, default)).Should().BeTrue();
        (await svc.IsAuthorizedAsync("u2", v.Id, default)).Should().BeFalse();
    }

    [Fact]
    public async Task AllowsCourseGrant()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b2", CreatedByUserId = "creator", CourseId = "c1", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        db.VideoAccessGrants.Add(new VideoAccessGrant { UserId = "u1", CourseId = "c1" });
        await db.SaveChangesAsync();

        var svc = new VideoEntitlementService(db, new FakeClock());
        (await svc.IsAuthorizedAsync("u1", v.Id, default)).Should().BeTrue();
    }

    [Fact]
    public async Task DeniesExpiredGrant()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b3", CreatedByUserId = "c", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        db.VideoAccessGrants.Add(new VideoAccessGrant
        {
            UserId = "u1", VideoId = v.Id,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1)
        });
        await db.SaveChangesAsync();

        var svc = new VideoEntitlementService(db, new FakeClock { UtcNow = DateTimeOffset.UtcNow });
        (await svc.IsAuthorizedAsync("u1", v.Id, default)).Should().BeFalse();
    }

    [Fact]
    public async Task DeniesRevokedGrant()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b4", CreatedByUserId = "c", Status = VideoStatus.Ready };
        db.Videos.Add(v);
        db.VideoAccessGrants.Add(new VideoAccessGrant { UserId = "u1", VideoId = v.Id, Revoked = true });
        await db.SaveChangesAsync();

        var svc = new VideoEntitlementService(db, new FakeClock());
        (await svc.IsAuthorizedAsync("u1", v.Id, default)).Should().BeFalse();
    }

    [Fact]
    public async Task DeniesDeletedVideo()
    {
        await using var db = NewDb();
        var v = new Video { Title = "t", BunnyVideoId = "b5", CreatedByUserId = "u1", Status = VideoStatus.Deleted };
        db.Videos.Add(v);
        await db.SaveChangesAsync();
        var svc = new VideoEntitlementService(db, new FakeClock());
        (await svc.IsAuthorizedAsync("u1", v.Id, default)).Should().BeFalse();
    }
}
