namespace VideoSecurity.Domain.Dtos;

public sealed record PlaybackSessionResponse(
    Guid SessionId,
    string? EmbedUrl,
    DateTimeOffset ExpiresAt,
    WatermarkPayload Watermark,
    string? HeartbeatToken = null,
    string PlaybackProvider = "BunnyStream",
    SecurePlaybackDescriptor? SecurePlayback = null);

public sealed record SecurePlaybackDescriptor(
    string Mode,
    string OfferEndpoint,
    IReadOnlyList<string> IceServers,
    string? SeekEndpoint = null,
    string? CloseEndpoint = null,
    double? DurationSeconds = null);

public sealed record SecurePlaybackOfferRequest(
    string Type,
    string Sdp);

public sealed record SecurePlaybackAnswerResponse(
    string Type,
    string Sdp);

public sealed record SecurePlaybackSeekRequest(
    double PositionSeconds,
    string? HeartbeatToken = null);

public sealed record SecurePlaybackSeekResponse(
    double PositionSeconds,
    string OfferEndpoint);

public sealed record SecurePlaybackCloseRequest(
    string? HeartbeatToken = null);

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
    string? DeviceFingerprint = null,
    string? HeartbeatToken = null);

public sealed record SecurityEventRequest(
    Guid? SessionId,
    Guid? VideoId,
    string Type,
    string? Metadata);
