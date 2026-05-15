using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;

namespace VideoSecurity.Web.Services;

public enum PublicPlaybackKind
{
    Demo,
    Embed
}

public sealed record PublicPlaybackBootstrap(
    string Id,
    Guid VideoId,
    PublicPlaybackKind Kind,
    DateTimeOffset ExpiresAt);

public sealed class PublicPlaybackBootstrapStore
{
    private const string Prefix = "public-playback-bootstrap:";
    private static readonly TimeSpan BootstrapTtl = TimeSpan.FromMinutes(2);
    private readonly IMemoryCache _cache;

    public PublicPlaybackBootstrapStore(IMemoryCache cache) => _cache = cache;

    public string Create(Guid videoId, PublicPlaybackKind kind)
    {
        var id = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var bootstrap = new PublicPlaybackBootstrap(id, videoId, kind, DateTimeOffset.UtcNow.Add(BootstrapTtl));
        _cache.Set(Prefix + id, bootstrap, BootstrapTtl);
        return id;
    }

    public bool TryConsume(string id, out PublicPlaybackBootstrap bootstrap)
    {
        bootstrap = default!;
        if (string.IsNullOrWhiteSpace(id)) return false;

        var key = Prefix + id;
        if (!_cache.TryGetValue<PublicPlaybackBootstrap>(key, out var found) || found is null)
            return false;

        _cache.Remove(key);
        if (found.ExpiresAt < DateTimeOffset.UtcNow)
            return false;

        bootstrap = found;
        return true;
    }
}
