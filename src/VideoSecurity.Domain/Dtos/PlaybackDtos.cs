namespace VideoSecurity.Domain.Dtos;

public sealed record PlaybackSessionResponse(
    Guid SessionId,
    string EmbedUrl,
    DateTimeOffset ExpiresAt,
    WatermarkPayload Watermark);

public sealed record WatermarkPayload(
    string DisplayText,
    string Token,
    long IssuedAtUnix,
    long ExpiresAtUnix);

public sealed record HeartbeatRequest(
    Guid SessionId,
    double PositionSeconds,
    bool DocumentVisible,
    bool DocumentFocused,
    bool WatermarkVisible = true,
    bool Fullscreen = true,
    string? DeviceFingerprint = null);

public sealed record SecurityEventRequest(
    Guid? SessionId,
    Guid? VideoId,
    string Type,
    string? Metadata);
