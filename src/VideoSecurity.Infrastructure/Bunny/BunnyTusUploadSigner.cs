using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.Infrastructure.Bunny;

/// <summary>
/// Builds TUS upload credentials per Bunny docs:
/// https://docs.bunny.net/stream/tus-resumable-uploads
/// AuthorizationSignature = SHA256(libraryId + apiKey + expirationTime + videoId)
/// </summary>
public sealed class BunnyTusUploadSigner : IBunnyTusUploadSigner
{
    private readonly IBunnyOptionsProvider _options;
    private readonly ISystemClock _clock;

    [ActivatorUtilitiesConstructor]
    public BunnyTusUploadSigner(IBunnyOptionsProvider options, ISystemClock clock)
    {
        _options = options;
        _clock = clock;
    }

    public BunnyTusUploadSigner(IOptions<BunnyOptions> opts, ISystemClock clock)
        : this(new StaticBunnyOptionsProvider(opts.Value), clock) { }

    public BunnyTusUploadCredentials CreateCredentials(string videoId, string fileName, TimeSpan ttl)
        => CreateCredentialsCore(videoId, fileName, ttl);

    public BunnyTusUploadCredentials CreateCredentials(string videoId, string fileName, TimeSpan ttl, long? estimatedFileSizeBytes)
    {
        var opts = _options.Current;
        if (estimatedFileSizeBytes is long size && size > 0)
        {
            var bps = opts.AssumedUploadBytesPerSecond > 0 ? opts.AssumedUploadBytesPerSecond : 1_500_000;
            // ceil(size / bps) seconds plus a 15-minute safety buffer.
            var estimatedSeconds = (size + bps - 1) / bps;
            var estimated = TimeSpan.FromSeconds(estimatedSeconds) + TimeSpan.FromMinutes(15);
            var oneHour = TimeSpan.FromHours(1);
            if (estimated > ttl) ttl = estimated;
            if (oneHour > ttl) ttl = oneHour;
        }
        return CreateCredentialsCore(videoId, fileName, ttl);
    }

    private BunnyTusUploadCredentials CreateCredentialsCore(string videoId, string fileName, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(videoId);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        if (ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));
        var opts = _options.Current;

        var expire = _clock.UtcNow.Add(ttl).ToUnixTimeSeconds();
        var raw = string.Concat(
            opts.LibraryId.ToString(CultureInfo.InvariantCulture),
            opts.ApiKey,
            expire.ToString(CultureInfo.InvariantCulture),
            videoId);

        var sig = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();

        return new BunnyTusUploadCredentials(
            TusEndpoint: opts.TusEndpoint,
            AuthorizationSignature: sig,
            AuthorizationExpire: expire,
            VideoId: videoId,
            LibraryId: opts.LibraryId,
            FileName: fileName);
    }
}
