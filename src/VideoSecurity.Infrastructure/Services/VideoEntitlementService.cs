using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Services;

public sealed class VideoEntitlementService : IVideoEntitlementService
{
    private readonly AppDbContext _db;
    private readonly ISystemClock _clock;

    public VideoEntitlementService(AppDbContext db, ISystemClock clock)
    {
        _db = db;
        _clock = clock;
    }

    public async Task<bool> IsAuthorizedAsync(string userId, Guid videoId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;

        var video = await _db.Videos.AsNoTracking()
            .FirstOrDefaultAsync(v => v.Id == videoId && v.Status != Domain.Entities.VideoStatus.Deleted, ct);
        if (video is null) return false;

        // Creators always have access.
        if (video.CreatedByUserId == userId) return true;

        var now = _clock.UtcNow;

        var candidateGrants = await _db.VideoAccessGrants.AsNoTracking()
            .Where(g => !g.Revoked
                        && g.UserId == userId
                        && (g.VideoId == videoId || (g.CourseId != null && video.CourseId != null && g.CourseId == video.CourseId)))
            .ToListAsync(ct);

        return candidateGrants.Any(g => g.ExpiresAt == null || g.ExpiresAt > now);
    }
}
