using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.Infrastructure.Bunny;

/// <summary>
/// Bunny CDN Advanced Token Authentication signer.
/// See https://docs.bunny.net/cdn/security/token-authentication/advanced.
/// Use only when a non-Embed CDN URL absolutely must be exposed.
/// </summary>
public sealed class BunnyCdnTokenSigner : IBunnyCdnTokenSigner
{
    private readonly IBunnyOptionsProvider _options;

    [ActivatorUtilitiesConstructor]
    public BunnyCdnTokenSigner(IBunnyOptionsProvider options) => _options = options;

    public BunnyCdnTokenSigner(IOptions<BunnyOptions> opts)
        : this(new StaticBunnyOptionsProvider(opts.Value)) { }

    public string BuildSignedCdnUrl(string path, DateTimeOffset expires, bool directoryToken = true, string? userIp = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var opts = _options.Current;
        if (string.IsNullOrEmpty(opts.CdnTokenKey))
            throw new InvalidOperationException("Bunny:CdnTokenKey not configured");
        if (string.IsNullOrEmpty(opts.CdnHostname))
            throw new InvalidOperationException("Bunny:CdnHostname not configured");

        var (resourcePath, queryParams) = SplitPathAndQuery(path);
        if (!resourcePath.StartsWith('/')) resourcePath = "/" + resourcePath;

        var expUnix = expires.ToUnixTimeSeconds();
        var signingParams = queryParams
            .Where(p => !ReservedTokenParameter(p.Key))
            .ToList();

        var signaturePath = resourcePath;
        string? tokenPath = null;
        if (directoryToken)
        {
            tokenPath = ParentDirectory(resourcePath);
            signaturePath = tokenPath;
            signingParams.Add(new KeyValuePair<string, string>("token_path", tokenPath));
        }

        var signingData = BuildSigningData(signingParams);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(opts.CdnTokenKey));
        var message = signaturePath + expUnix + signingData + (userIp ?? string.Empty);
        var token = "HS256-" + Base64Url(hmac.ComputeHash(Encoding.UTF8.GetBytes(message)));
        var host = opts.CdnHostname.TrimEnd('/');

        if (directoryToken)
        {
            var tokenPrefix = $"/bcdn_token={Uri.EscapeDataString(token)}&expires={expUnix}&token_path={Uri.EscapeDataString(tokenPath!)}";
            return $"https://{host}{tokenPrefix}{resourcePath}{BuildQueryString(queryParams.Where(p => !ReservedTokenParameter(p.Key)))}";
        }

        var finalParams = queryParams.Where(p => !ReservedTokenParameter(p.Key)).ToList();
        finalParams.Add(new KeyValuePair<string, string>("token", token));
        finalParams.Add(new KeyValuePair<string, string>("expires", expUnix.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return $"https://{host}{resourcePath}{BuildQueryString(finalParams)}";
    }

    private static bool ReservedTokenParameter(string key) =>
        string.Equals(key, "token", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(key, "expires", StringComparison.OrdinalIgnoreCase);

    private static string ParentDirectory(string path)
    {
        var lastSlash = path.LastIndexOf('/');
        return lastSlash <= 0 ? "/" : path[..(lastSlash + 1)];
    }

    private static (string Path, List<KeyValuePair<string, string>> Query) SplitPathAndQuery(string path)
    {
        if (Uri.TryCreate(path, UriKind.Absolute, out var absolute))
            path = absolute.PathAndQuery;

        var qIndex = path.IndexOf('?', StringComparison.Ordinal);
        if (qIndex < 0) return (path, new List<KeyValuePair<string, string>>());

        var resourcePath = path[..qIndex];
        var query = path[(qIndex + 1)..];
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=', StringComparison.Ordinal);
            var key = eq < 0 ? part : part[..eq];
            var value = eq < 0 ? string.Empty : part[(eq + 1)..];
            pairs.Add(new KeyValuePair<string, string>(Uri.UnescapeDataString(key), Uri.UnescapeDataString(value)));
        }
        return (resourcePath, pairs);
    }

    private static string BuildSigningData(IEnumerable<KeyValuePair<string, string>> pairs) =>
        string.Join('&', pairs
            .Where(p => !ReservedTokenParameter(p.Key))
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .ThenBy(p => p.Value, StringComparer.Ordinal)
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));

    private static string BuildQueryString(IEnumerable<KeyValuePair<string, string>> pairs)
    {
        var encoded = pairs
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}")
            .ToArray();
        return encoded.Length == 0 ? string.Empty : "?" + string.Join('&', encoded);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
