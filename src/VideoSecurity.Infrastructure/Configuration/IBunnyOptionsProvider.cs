namespace VideoSecurity.Infrastructure.Configuration;

public interface IBunnyOptionsProvider
{
    BunnyOptions Current { get; }
    Task<BunnyOptions> GetAsync(CancellationToken ct = default);
    Task SaveAsync(BunnyOptions options, string? updatedByUserId, CancellationToken ct = default);
    IReadOnlyList<string> Validate(BunnyOptions options);
}