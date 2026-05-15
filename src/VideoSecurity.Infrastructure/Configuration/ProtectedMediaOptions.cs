namespace VideoSecurity.Infrastructure.Configuration;

public sealed class ProtectedMediaOptions
{
    public const string SectionName = "ProtectedMedia";

    public string RootPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "protected-media");

    public long MaxSourceBytes { get; set; } = 10L * 1024 * 1024 * 1024;

    public string[] AllowedExtensions { get; set; } = [".mp4", ".mkv", ".mov", ".avi", ".webm"];
}
