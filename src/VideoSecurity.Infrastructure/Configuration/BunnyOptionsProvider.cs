using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Infrastructure.Configuration;

public sealed class BunnyOptionsProvider : IBunnyOptionsProvider
{
    private static readonly Regex CdnHostnameRegex =
        new(@"^[a-z0-9-]+\.b-cdn\.net$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IDataProtector _protector;
    private readonly BunnyOptions _configuredDefaults;
    private readonly ILogger<BunnyOptionsProvider> _logger;
    private readonly object _gate = new();
    private BunnyOptions? _current;

    public BunnyOptionsProvider(
        IServiceScopeFactory scopeFactory,
        IDataProtectionProvider dataProtection,
        IConfiguration config,
        ILogger<BunnyOptionsProvider> logger)
    {
        _scopeFactory = scopeFactory;
        _protector = dataProtection.CreateProtector("VideoSecurity.BunnyRuntimeSettings.v1");
        var defaults = new BunnyOptions();
        config.GetSection(BunnyOptions.SectionName).Bind(defaults);
        _configuredDefaults = Clone(defaults);
        _logger = logger;
    }

    public BunnyOptions Current
    {
        get
        {
            lock (_gate)
            {
                if (_current is not null) return Clone(_current);
            }

            return GetAsync().GetAwaiter().GetResult();
        }
    }

    public async Task<BunnyOptions> GetAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_current is not null) return Clone(_current);
        }

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var settings = await db.BunnyRuntimeSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
        var options = settings is null ? Clone(_configuredDefaults) : FromSettings(settings);

        lock (_gate)
        {
            _current = Clone(options);
        }

        return options;
    }

    public async Task SaveAsync(BunnyOptions options, string? updatedByUserId, CancellationToken ct = default)
    {
        var failures = Validate(options);
        if (failures.Count > 0)
            throw new InvalidOperationException(string.Join(" ", failures));

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var settings = await db.BunnyRuntimeSettings.FirstOrDefaultAsync(s => s.Id == 1, ct);
        if (settings is null)
        {
            settings = new BunnyRuntimeSettings { Id = 1 };
            db.BunnyRuntimeSettings.Add(settings);
        }

        Apply(options, settings, updatedByUserId);
        await db.SaveChangesAsync(ct);

        lock (_gate)
        {
            _current = Clone(options);
        }
    }

    public IReadOnlyList<string> Validate(BunnyOptions options)
    {
        var failures = new List<string>();
        if (options.LibraryId <= 0) failures.Add("Library ID must be greater than zero.");
        if (!IsStrongSecret(options.ApiKey)) failures.Add("API key must be at least 16 characters and not a placeholder.");
        if (!IsStrongSecret(options.EmbedTokenKey)) failures.Add("Embed token key must be at least 16 characters and not a placeholder.");
        if (string.IsNullOrWhiteSpace(options.CdnHostname) || !CdnHostnameRegex.IsMatch(options.CdnHostname)) failures.Add("CDN hostname must look like vz-example.b-cdn.net.");
        if (!string.IsNullOrWhiteSpace(options.CdnTokenKey) && options.CdnTokenKey.Length < 16) failures.Add("CDN token key must be blank or at least 16 characters.");
        if (!string.IsNullOrWhiteSpace(options.WebhookSecret) && options.WebhookSecret.Length < 16) failures.Add("Webhook secret must be blank or at least 16 characters.");
        if (!string.IsNullOrWhiteSpace(options.PrivacyHashPepper) && options.PrivacyHashPepper.Length < 32) failures.Add("Privacy hash pepper must be blank or at least 32 characters.");
        if (!Uri.TryCreate(options.ApiBaseUrl, UriKind.Absolute, out _)) failures.Add("API base URL must be an absolute URL.");
        if (!Uri.TryCreate(options.TusEndpoint, UriKind.Absolute, out _)) failures.Add("TUS endpoint must be an absolute URL.");
        if (!Uri.TryCreate(options.EmbedBaseUrl, UriKind.Absolute, out _)) failures.Add("Embed base URL must be an absolute URL.");
        if (options.DefaultSessionTtl <= TimeSpan.Zero || options.DefaultSessionTtl > TimeSpan.FromHours(2)) failures.Add("Playback session TTL must be between 1 second and 2 hours.");
        if (options.DefaultUploadTtl <= TimeSpan.Zero || options.DefaultUploadTtl > TimeSpan.FromDays(7)) failures.Add("Upload credential TTL must be between 1 second and 7 days.");
        if (options.AssumedUploadBytesPerSecond <= 0) failures.Add("Assumed upload bytes/second must be greater than zero.");
        if (options.WebhookEventDedupeWindow <= TimeSpan.Zero || options.WebhookEventDedupeWindow > TimeSpan.FromDays(30)) failures.Add("Webhook dedupe window must be between 1 second and 30 days.");
        return failures;
    }

    private BunnyOptions FromSettings(BunnyRuntimeSettings settings) => new()
    {
        LibraryId = settings.LibraryId,
        ApiKey = Unprotect(settings.ApiKeyProtected),
        EmbedTokenKey = Unprotect(settings.EmbedTokenKeyProtected),
        CdnHostname = settings.CdnHostname,
        CdnTokenKey = UnprotectOptional(settings.CdnTokenKeyProtected),
        ApiBaseUrl = settings.ApiBaseUrl,
        TusEndpoint = settings.TusEndpoint,
        EmbedBaseUrl = settings.EmbedBaseUrl,
        DefaultSessionTtl = TimeSpan.FromSeconds(settings.DefaultSessionTtlSeconds),
        DefaultUploadTtl = TimeSpan.FromSeconds(settings.DefaultUploadTtlSeconds),
        LockSessionToIp = settings.LockSessionToIp,
        PrivacyHashPepper = UnprotectOptional(settings.PrivacyHashPepperProtected),
        WebhookSecret = UnprotectOptional(settings.WebhookSecretProtected),
        AssumedUploadBytesPerSecond = settings.AssumedUploadBytesPerSecond,
        WebhookEventDedupeWindow = TimeSpan.FromSeconds(settings.WebhookEventDedupeWindowSeconds)
    };

    private void Apply(BunnyOptions options, BunnyRuntimeSettings settings, string? updatedByUserId)
    {
        settings.LibraryId = options.LibraryId;
        settings.ApiKeyProtected = Protect(options.ApiKey);
        settings.EmbedTokenKeyProtected = Protect(options.EmbedTokenKey);
        settings.CdnHostname = options.CdnHostname.Trim();
        settings.CdnTokenKeyProtected = ProtectOptional(options.CdnTokenKey);
        settings.ApiBaseUrl = options.ApiBaseUrl.Trim().TrimEnd('/');
        settings.TusEndpoint = options.TusEndpoint.Trim();
        settings.EmbedBaseUrl = options.EmbedBaseUrl.Trim().TrimEnd('/');
        settings.DefaultSessionTtlSeconds = checked((int)options.DefaultSessionTtl.TotalSeconds);
        settings.DefaultUploadTtlSeconds = checked((int)options.DefaultUploadTtl.TotalSeconds);
        settings.LockSessionToIp = options.LockSessionToIp;
        settings.PrivacyHashPepperProtected = ProtectOptional(options.PrivacyHashPepper);
        settings.WebhookSecretProtected = ProtectOptional(options.WebhookSecret);
        settings.AssumedUploadBytesPerSecond = options.AssumedUploadBytesPerSecond;
        settings.WebhookEventDedupeWindowSeconds = checked((int)options.WebhookEventDedupeWindow.TotalSeconds);
        settings.UpdatedAt = DateTimeOffset.UtcNow;
        settings.UpdatedByUserId = updatedByUserId;
    }

    private string Protect(string value) => _protector.Protect(value.Trim());
    private string? ProtectOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : Protect(value);

    private string Unprotect(string value)
    {
        try { return _protector.Unprotect(value); }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to unprotect Bunny runtime setting.");
            return string.Empty;
        }
    }

    private string? UnprotectOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : Unprotect(value);

    private static BunnyOptions Clone(BunnyOptions source) => new()
    {
        LibraryId = source.LibraryId,
        ApiKey = source.ApiKey,
        EmbedTokenKey = source.EmbedTokenKey,
        CdnHostname = source.CdnHostname,
        CdnTokenKey = source.CdnTokenKey,
        ApiBaseUrl = source.ApiBaseUrl,
        TusEndpoint = source.TusEndpoint,
        EmbedBaseUrl = source.EmbedBaseUrl,
        DefaultSessionTtl = source.DefaultSessionTtl,
        DefaultUploadTtl = source.DefaultUploadTtl,
        LockSessionToIp = source.LockSessionToIp,
        PrivacyHashPepper = source.PrivacyHashPepper,
        WebhookSecret = source.WebhookSecret,
        AssumedUploadBytesPerSecond = source.AssumedUploadBytesPerSecond,
        WebhookEventDedupeWindow = source.WebhookEventDedupeWindow
    };

    private static bool IsStrongSecret(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 16) return false;
        var placeholders = new[] { "<library-api-key>", "your-", "replace-me", "replace_with_user_secrets_or_env", "changeme", "xxxx" };
        return !placeholders.Any(p => value.Contains(p, StringComparison.OrdinalIgnoreCase));
    }
}