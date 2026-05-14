using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace VideoSecurity.Infrastructure.Configuration;

/// <summary>
/// Stronger startup validation for <see cref="BunnyOptions"/>. Runs in addition to data
/// annotation + delegate validation already wired in <c>DependencyInjection</c>.
/// </summary>
public sealed class BunnyOptionsValidator : IValidateOptions<BunnyOptions>
{
    private static readonly string[] Placeholders =
    {
        "<library-api-key>",
        "your-",
        "replace-me",
        "replace_with_user_secrets_or_env",
        "changeme",
        "xxxx"
    };

    private static readonly Regex CdnHostnameRegex =
        new(@"^[a-z0-9-]+\.b-cdn\.net$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly ILogger<BunnyOptionsValidator> _logger;

    public BunnyOptionsValidator(ILogger<BunnyOptionsValidator> logger)
    {
        _logger = logger;
    }

    public ValidateOptionsResult Validate(string? name, BunnyOptions options)
    {
        var failures = new List<string>();

        if (options.LibraryId <= 0)
        {
            failures.Add("Bunny:LibraryId must be > 0.");
        }

        if (!IsStrongSecret(options.ApiKey))
        {
            failures.Add("Bunny:ApiKey must be at least 16 characters and not a placeholder.");
        }

        if (!IsStrongSecret(options.EmbedTokenKey))
        {
            failures.Add("Bunny:EmbedTokenKey must be at least 16 characters and not a placeholder.");
        }

        if (string.IsNullOrWhiteSpace(options.CdnHostname) ||
            !CdnHostnameRegex.IsMatch(options.CdnHostname))
        {
            failures.Add("Bunny:CdnHostname must match '^[a-z0-9-]+\\.b-cdn\\.net$'.");
        }

        if (string.IsNullOrWhiteSpace(options.PrivacyHashPepper) ||
            options.PrivacyHashPepper.Length < 32)
        {
            _logger.LogWarning(
                "Bunny:PrivacyHashPepper is missing or shorter than 32 characters. " +
                "IP/UA audit hashes will fall back to EmbedTokenKey, which is less private. " +
                "Set a dedicated 32+ character random pepper in production.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static bool IsStrongSecret(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 16)
        {
            return false;
        }

        foreach (var placeholder in Placeholders)
        {
            if (value.Contains(placeholder, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }
}
