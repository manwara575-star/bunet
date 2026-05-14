using FluentAssertions;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Bunny;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.UnitTests;

public class FakeClock : ISystemClock
{
    public DateTimeOffset UtcNow { get; set; } = new DateTimeOffset(2026, 5, 14, 12, 0, 0, TimeSpan.Zero);
}

public class BunnyEmbedTokenSignerTests
{
    private static IOptions<BunnyOptions> Opts(BunnyOptions o) => Options.Create(o);

    [Fact]
    public void BuildsExpectedSignedUrl_WithSha256()
    {
        var opts = new BunnyOptions
        {
            LibraryId = 12345,
            EmbedTokenKey = "test-key",
            EmbedBaseUrl = "https://iframe.mediadelivery.net"
        };
        var signer = new BunnyEmbedTokenSigner(Opts(opts));
        var expires = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var url = signer.BuildSignedEmbedUrl("vid-abc", expires, "user1", "sess1");

        url.Should().StartWith("https://iframe.mediadelivery.net/embed/12345/vid-abc?token=");
        url.Should().Contain("&expires=" + expires.ToUnixTimeSeconds());
        // Token must be a 64-char lowercase hex SHA256.
        var token = url.Split("token=")[1].Split('&')[0];
        token.Should().HaveLength(64);
        token.Should().MatchRegex("^[a-f0-9]{64}$");

        var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("test-key" + "vid-abc" + expires.ToUnixTimeSeconds())))
            .ToLowerInvariant();
        token.Should().Be(expected);
        url.Should().NotContain("sid=");
    }

    [Fact]
    public void Throws_WhenKeyMissing()
    {
        var signer = new BunnyEmbedTokenSigner(Opts(new BunnyOptions { LibraryId = 1, EmbedTokenKey = "" }));
        var act = () => signer.BuildSignedEmbedUrl("v", DateTimeOffset.UtcNow.AddMinutes(5), null, null);
        act.Should().Throw<InvalidOperationException>();
    }
}

public class BunnyTusUploadSignerTests
{
    [Fact]
    public void GeneratesSha256Signature_FromLibraryApiKeyExpireVideoId()
    {
        var opts = new BunnyOptions { LibraryId = 100, ApiKey = "k", EmbedTokenKey = "x" };
        var clock = new FakeClock();
        var signer = new BunnyTusUploadSigner(Options.Create(opts), clock);

        var creds = signer.CreateCredentials("vid", "movie.mp4", TimeSpan.FromHours(1));
        creds.AuthorizationSignature.Should().HaveLength(64);
        creds.AuthorizationSignature.Should().MatchRegex("^[a-f0-9]{64}$");
        creds.AuthorizationExpire.Should().Be(clock.UtcNow.AddHours(1).ToUnixTimeSeconds());
        var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("100" + "k" + creds.AuthorizationExpire + "vid")))
            .ToLowerInvariant();
        creds.AuthorizationSignature.Should().Be(expected);
        creds.VideoId.Should().Be("vid");
        creds.LibraryId.Should().Be(100);
    }

    [Fact]
    public void RejectsZeroTtl()
    {
        var signer = new BunnyTusUploadSigner(Options.Create(new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "x" }), new FakeClock());
        var act = () => signer.CreateCredentials("v", "f.mp4", TimeSpan.Zero);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void DynamicTtl_ScalesWithFileSizeHint_AndIsAtLeastOneHour()
    {
        var opts = new BunnyOptions
        {
            LibraryId = 100,
            ApiKey = "k",
            EmbedTokenKey = "x",
            AssumedUploadBytesPerSecond = 1_500_000
        };
        var clock = new FakeClock();
        var signer = new BunnyTusUploadSigner(Options.Create(opts), clock);

        const long fiveGb = 5L * 1024 * 1024 * 1024;
        var providedTtl = TimeSpan.FromMinutes(10); // small; must be expanded

        var creds = signer.CreateCredentials("vid", "movie.mp4", providedTtl, fiveGb);

        var expectedSeconds = (fiveGb + opts.AssumedUploadBytesPerSecond - 1) / opts.AssumedUploadBytesPerSecond;
        var expectedTtl = TimeSpan.FromSeconds(expectedSeconds) + TimeSpan.FromMinutes(15);
        if (expectedTtl < TimeSpan.FromHours(1)) expectedTtl = TimeSpan.FromHours(1);

        var expectedExpire = clock.UtcNow.Add(expectedTtl).ToUnixTimeSeconds();
        creds.AuthorizationExpire.Should().Be(expectedExpire);
        (creds.AuthorizationExpire - clock.UtcNow.ToUnixTimeSeconds()).Should().BeGreaterThanOrEqualTo(3600);
    }

    [Fact]
    public void DynamicTtl_FloorsToOneHour_ForTinyFiles()
    {
        var opts = new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "x" };
        var clock = new FakeClock();
        var signer = new BunnyTusUploadSigner(Options.Create(opts), clock);

        var creds = signer.CreateCredentials("vid", "tiny.mp4", TimeSpan.FromMinutes(5), estimatedFileSizeBytes: 1024);

        var expectedExpire = clock.UtcNow.AddHours(1).ToUnixTimeSeconds();
        creds.AuthorizationExpire.Should().Be(expectedExpire);
    }

    [Fact]
    public void DynamicTtl_KeepsLargerProvidedTtl()
    {
        var opts = new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "x" };
        var clock = new FakeClock();
        var signer = new BunnyTusUploadSigner(Options.Create(opts), clock);

        var bigTtl = TimeSpan.FromHours(8);
        var creds = signer.CreateCredentials("vid", "tiny.mp4", bigTtl, estimatedFileSizeBytes: 1024);

        creds.AuthorizationExpire.Should().Be(clock.UtcNow.Add(bigTtl).ToUnixTimeSeconds());
    }
}

public class BunnyCdnTokenSignerTests
{
    [Fact]
    public void DirectoryToken_ProducesPathBasedHs256UrlBoundToParentPath()
    {
        var opts = new BunnyOptions
        {
            LibraryId = 1,
            ApiKey = "k",
            EmbedTokenKey = "x",
            CdnHostname = "vz-test.b-cdn.net",
            CdnTokenKey = "cdn-secret"
        };
        var signer = new BunnyCdnTokenSigner(Options.Create(opts));
        var expires = DateTimeOffset.FromUnixTimeSeconds(1893456000);
        var url = signer.BuildSignedCdnUrl("/abc/playlist.m3u8", expires, directoryToken: true);

        var expectedToken = CdnToken("cdn-secret", "/abc/", expires.ToUnixTimeSeconds(), "token_path=%2Fabc%2F");
        url.Should().Be($"https://vz-test.b-cdn.net/bcdn_token={expectedToken}&expires=1893456000&token_path=%2Fabc%2F/abc/playlist.m3u8");
    }

    [Fact]
    public void QueryToken_SignsSortedQueryParams()
    {
        var opts = new BunnyOptions
        {
            LibraryId = 1,
            ApiKey = "k",
            EmbedTokenKey = "x",
            CdnHostname = "vz-test.b-cdn.net",
            CdnTokenKey = "cdn-secret"
        };
        var signer = new BunnyCdnTokenSigner(Options.Create(opts));
        var expires = DateTimeOffset.FromUnixTimeSeconds(1893456000);

        var url = signer.BuildSignedCdnUrl("/video/file.mp4?z=last&a=first", expires, directoryToken: false);

        var expectedToken = CdnToken("cdn-secret", "/video/file.mp4", expires.ToUnixTimeSeconds(), "a=first&z=last");
        url.Should().Be($"https://vz-test.b-cdn.net/video/file.mp4?z=last&a=first&token={expectedToken}&expires=1893456000");
    }

    [Fact]
    public void Throws_WhenCdnKeyMissing()
    {
        var signer = new BunnyCdnTokenSigner(Options.Create(new BunnyOptions { LibraryId = 1, ApiKey = "k", EmbedTokenKey = "x", CdnHostname = "h" }));
        var act = () => signer.BuildSignedCdnUrl("/a", DateTimeOffset.UtcNow.AddMinutes(1));
        act.Should().Throw<InvalidOperationException>();
    }

    private static string CdnToken(string key, string signaturePath, long expires, string signingData)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(signaturePath + expires + signingData));
        return "HS256-" + Convert.ToBase64String(hash).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
