using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.Infrastructure.Bunny;

/// <summary>
/// Signs Bunny Embed iframe URLs.
///   token = SHA256(tokenKey + videoId + expires)
///   url   = {EmbedBaseUrl}/embed/{libraryId}/{videoId}?token={token}&expires={expires}
/// Per https://docs.bunny.net/stream/token-authentication
/// </summary>
public sealed class BunnyEmbedTokenSigner : IBunnyEmbedTokenSigner
{
    private readonly IBunnyOptionsProvider _options;

    [ActivatorUtilitiesConstructor]
    public BunnyEmbedTokenSigner(IBunnyOptionsProvider options) => _options = options;

    public BunnyEmbedTokenSigner(IOptions<BunnyOptions> opts)
        : this(new StaticBunnyOptionsProvider(opts.Value)) { }

    public string BuildSignedEmbedUrl(string videoId, DateTimeOffset expires, string? userId, string? sessionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(videoId);
        var opts = _options.Current;
        if (string.IsNullOrEmpty(opts.EmbedTokenKey))
            throw new InvalidOperationException("Bunny:EmbedTokenKey not configured");

        var expUnix = expires.ToUnixTimeSeconds();
        var raw = opts.EmbedTokenKey + videoId + expUnix.ToString(CultureInfo.InvariantCulture);
        var token = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();

        var sb = new StringBuilder()
            .Append(opts.EmbedBaseUrl.TrimEnd('/'))
            .Append("/embed/")
            .Append(opts.LibraryId)
            .Append('/')
            .Append(videoId)
            .Append("?token=").Append(token)
            .Append("&expires=").Append(expUnix);

        return sb.ToString();
    }
}
