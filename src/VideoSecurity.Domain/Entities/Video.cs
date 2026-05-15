namespace VideoSecurity.Domain.Entities;

public class Video
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>Bunny Stream library ID this video lives in.</summary>
    public long BunnyLibraryId { get; set; }

    /// <summary>Bunny video GUID returned by the create-video API.</summary>
    public string BunnyVideoId { get; set; } = string.Empty;

    /// <summary>Optional Bunny collection / course mapping.</summary>
    public string? BunnyCollectionId { get; set; }

    public string? CourseId { get; set; }

    public VideoStatus Status { get; set; } = VideoStatus.Created;

    /// <summary>Always true in v1 — every video is DRM-protected.</summary>
    public bool IsProtected { get; set; } = true;

    /// <summary>Allows this video to be exposed through the public sales/demo route.</summary>
    public bool AllowPublicDemo { get; set; }

    public double DurationSeconds { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    public string CreatedByUserId { get; set; } = string.Empty;

    public VideoSensitivityTier SensitivityTier { get; set; } = VideoSensitivityTier.Standard;
    public Guid? PolicyId { get; set; }
}
