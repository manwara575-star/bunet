namespace VideoSecurity.Infrastructure.Configuration;

public sealed class StaticBunnyOptionsProvider : IBunnyOptionsProvider
{
    private BunnyOptions _options;

    public StaticBunnyOptionsProvider(BunnyOptions options) => _options = options;

    public BunnyOptions Current => _options;

    public Task<BunnyOptions> GetAsync(CancellationToken ct = default) => Task.FromResult(_options);

    public Task SaveAsync(BunnyOptions options, string? updatedByUserId, CancellationToken ct = default)
    {
        _options = options;
        return Task.CompletedTask;
    }

    public IReadOnlyList<string> Validate(BunnyOptions options) => Array.Empty<string>();
}