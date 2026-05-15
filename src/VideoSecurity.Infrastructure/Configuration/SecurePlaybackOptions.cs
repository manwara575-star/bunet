namespace VideoSecurity.Infrastructure.Configuration;

public sealed class SecurePlaybackOptions
{
    public const string SectionName = "SecurePlayback";

    public bool Enabled { get; set; }

    public string? WhepEndpointTemplate { get; set; }

    public string? WhepBearerToken { get; set; }

    public string[] IceServers { get; set; } = [];

    public TimeSpan OfferTimeout { get; set; } = TimeSpan.FromSeconds(15);

    public bool StartFfmpegOnSessionCreate { get; set; }

    public string FfmpegPath { get; set; } = "ffmpeg";

    public string? RtspPublishUrlTemplate { get; set; }

    public bool BurnWatermark { get; set; } = true;

    public int WatermarkFontSize { get; set; } = 28;
}
