using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Entities;

namespace VideoSecurity.Infrastructure.Persistence;

public class AppDbContext : IdentityDbContext<ApplicationUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public override int SaveChanges()
    {
        SetSortableUtcTicks();
        return base.SaveChanges();
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        SetSortableUtcTicks();
        return base.SaveChangesAsync(cancellationToken);
    }

    public DbSet<Video> Videos => Set<Video>();
    public DbSet<VideoAccessGrant> VideoAccessGrants => Set<VideoAccessGrant>();
    public DbSet<PlaybackSession> PlaybackSessions => Set<PlaybackSession>();
    public DbSet<VideoProgress> VideoProgress => Set<VideoProgress>();
    public DbSet<VideoSecurityEvent> VideoSecurityEvents => Set<VideoSecurityEvent>();
    public DbSet<BunnyWebhookReceipt> BunnyWebhookReceipts => Set<BunnyWebhookReceipt>();
    public DbSet<VideoSecurityPolicy> VideoSecurityPolicies => Set<VideoSecurityPolicy>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<SigningKeyVersion> SigningKeyVersions => Set<SigningKeyVersion>();
    public DbSet<WebhookEvent> WebhookEvents => Set<WebhookEvent>();
    public DbSet<BunnyRuntimeSettings> BunnyRuntimeSettings => Set<BunnyRuntimeSettings>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<Video>(e =>
        {
            e.HasIndex(x => x.BunnyVideoId).IsUnique();
            e.Property(x => x.Title).HasMaxLength(512).IsRequired();
            e.Property(x => x.BunnyVideoId).HasMaxLength(64).IsRequired();
            e.Property(x => x.CourseId).HasMaxLength(64);
            e.Property(x => x.BunnyCollectionId).HasMaxLength(64);
            e.Property(x => x.CreatedByUserId).HasMaxLength(450).IsRequired();
        });

        b.Entity<VideoAccessGrant>(e =>
        {
            e.HasIndex(x => new { x.UserId, x.VideoId });
            e.HasIndex(x => new { x.UserId, x.CourseId });
            e.HasIndex(x => x.VideoId);
            e.HasIndex(x => x.CourseId);
            e.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            e.Property(x => x.CourseId).HasMaxLength(64);
        });

        b.Entity<PlaybackSession>(e =>
        {
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.VideoId);
            e.HasIndex(x => x.ExpiresAt);
            e.HasIndex(x => x.ExpiresAtUtcTicks);
            e.HasIndex(x => new { x.UserId, x.VideoId });
            e.HasIndex(x => new { x.Revoked, x.ExpiresAt });
            e.HasIndex(x => new { x.Revoked, x.ExpiresAtUtcTicks });
            e.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            e.Property(x => x.IpHash).HasMaxLength(128).IsRequired();
            e.Property(x => x.UserAgentHash).HasMaxLength(128).IsRequired();
            e.Property(x => x.RevocationReason).HasMaxLength(256);
            e.Property(x => x.WatermarkPayload).HasMaxLength(512).IsRequired();
        });

        b.Entity<VideoProgress>(e =>
        {
            e.HasIndex(x => new { x.UserId, x.VideoId }).IsUnique();
            e.Property(x => x.UserId).HasMaxLength(450).IsRequired();
        });

        b.Entity<VideoSecurityEvent>(e =>
        {
            e.HasIndex(x => x.CreatedAt);
            e.HasIndex(x => x.SessionId);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => new { x.VideoId, x.CreatedAt });
            e.HasIndex(x => new { x.Type, x.CreatedAt });
            e.Property(x => x.UserId).HasMaxLength(450);
            e.Property(x => x.IpHash).HasMaxLength(128).IsRequired();
            e.Property(x => x.UserAgentHash).HasMaxLength(128).IsRequired();
        });

        b.Entity<BunnyWebhookReceipt>(e =>
        {
            e.HasIndex(x => x.BodyHash).IsUnique();
            e.HasIndex(x => x.ReceivedAt);
            e.Property(x => x.BodyHash).HasMaxLength(64).IsRequired();
            e.Property(x => x.SignatureHash).HasMaxLength(64).IsRequired();
            e.Property(x => x.VideoGuid).HasMaxLength(64);
        });

        b.Entity<VideoSecurityPolicy>(e =>
        {
            e.HasIndex(x => x.Tier).IsUnique();
        });

        b.Entity<AuditLog>(e =>
        {
            e.HasIndex(x => x.CreatedAt);
            e.HasIndex(x => x.CreatedAtUtcTicks);
            e.HasIndex(x => x.ActorUserId);
            e.Property(x => x.ActorUserId).HasMaxLength(450).IsRequired();
            e.Property(x => x.EntityType).HasMaxLength(128);
            e.Property(x => x.EntityId).HasMaxLength(128);
            e.Property(x => x.MetadataJson).HasMaxLength(4000);
            e.Property(x => x.IpHash).HasMaxLength(128).IsRequired();
            e.Property(x => x.UserAgentHash).HasMaxLength(128).IsRequired();
        });

        b.Entity<SigningKeyVersion>(e =>
        {
            e.HasIndex(x => new { x.Purpose, x.Version }).IsUnique();
            e.Property(x => x.Notes).HasMaxLength(512);
        });

        b.Entity<WebhookEvent>(e =>
        {
            e.HasIndex(x => x.EventId).IsUnique();
            e.HasIndex(x => x.ReceivedAt);
            e.Property(x => x.EventId).HasMaxLength(128).IsRequired();
            e.Property(x => x.VideoGuid).HasMaxLength(64).IsRequired();
            e.Property(x => x.RawPayload).HasMaxLength(8000);
            e.Property(x => x.LastError).HasMaxLength(2000);
        });

        b.Entity<BunnyRuntimeSettings>(e =>
        {
            e.Property(x => x.ApiKeyProtected).HasMaxLength(4000).IsRequired();
            e.Property(x => x.EmbedTokenKeyProtected).HasMaxLength(4000).IsRequired();
            e.Property(x => x.CdnHostname).HasMaxLength(255).IsRequired();
            e.Property(x => x.CdnTokenKeyProtected).HasMaxLength(4000);
            e.Property(x => x.ApiBaseUrl).HasMaxLength(512).IsRequired();
            e.Property(x => x.TusEndpoint).HasMaxLength(512).IsRequired();
            e.Property(x => x.EmbedBaseUrl).HasMaxLength(512).IsRequired();
            e.Property(x => x.PrivacyHashPepperProtected).HasMaxLength(4000);
            e.Property(x => x.WebhookSecretProtected).HasMaxLength(4000);
            e.Property(x => x.UpdatedByUserId).HasMaxLength(450);
        });
    }

    private void SetSortableUtcTicks()
    {
        foreach (var entry in ChangeTracker.Entries<PlaybackSession>()
                     .Where(e => e.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.CreatedAtUtcTicks = entry.Entity.CreatedAt.UtcDateTime.Ticks;
            entry.Entity.ExpiresAtUtcTicks = entry.Entity.ExpiresAt.UtcDateTime.Ticks;
        }

        foreach (var entry in ChangeTracker.Entries<AuditLog>()
                     .Where(e => e.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.CreatedAtUtcTicks = entry.Entity.CreatedAt.UtcDateTime.Ticks;
        }
    }
}
