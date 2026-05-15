using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Bunny;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Health;
using VideoSecurity.Infrastructure.Observability;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Infrastructure.Services;

namespace VideoSecurity.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddVideoSecurityInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.AddOptions<BunnyOptions>()
            .Bind(config.GetSection(BunnyOptions.SectionName));
        services.AddOptions<ProtectedMediaOptions>()
            .Bind(config.GetSection(ProtectedMediaOptions.SectionName));
        services.AddOptions<SecurePlaybackOptions>()
            .Bind(config.GetSection(SecurePlaybackOptions.SectionName));

        services.AddSingleton<IBunnyOptionsProvider, BunnyOptionsProvider>();

        var connectionString = config.GetConnectionString("DefaultConnection")
            ?? "Data Source=videosecurity.db";

        services.AddDbContext<AppDbContext>(o => o.UseSqlite(connectionString));

        services.AddMemoryCache();

        services.AddSingleton<ISystemClock, SystemClock>();
        services.AddSingleton<SecurityMetrics>();

        services.AddHttpClient<IBunnyStreamClient, BunnyStreamClient>();

        services.AddSingleton<IBunnyTusUploadSigner>(sp => new BunnyTusUploadSigner(
            sp.GetRequiredService<IBunnyOptionsProvider>(),
            sp.GetRequiredService<ISystemClock>()));
        services.AddSingleton<IBunnyEmbedTokenSigner>(sp => new BunnyEmbedTokenSigner(
            sp.GetRequiredService<IBunnyOptionsProvider>()));
        services.AddSingleton<IBunnyCdnTokenSigner>(sp => new BunnyCdnTokenSigner(
            sp.GetRequiredService<IBunnyOptionsProvider>()));

        services.AddScoped<IVideoEntitlementService, VideoEntitlementService>();
        services.AddSingleton<IProtectedMediaStorage, FileSystemProtectedMediaStorage>();
        services.AddSingleton<ISecureMediaWorker, FfmpegSecureMediaWorker>();
        services.AddScoped<IVideoSecurityPolicyService, VideoSecurityPolicyService>();
        services.AddScoped<IPlaybackSessionService>(sp => new PlaybackSessionService(
            sp.GetRequiredService<AppDbContext>(),
            sp.GetRequiredService<IVideoEntitlementService>(),
            sp.GetRequiredService<IBunnyEmbedTokenSigner>(),
            sp.GetRequiredService<IBunnyOptionsProvider>(),
            sp.GetRequiredService<ISystemClock>(),
            sp.GetRequiredService<IVideoSecurityPolicyService>(),
            sp.GetRequiredService<SecurityMetrics>(),
            sp.GetRequiredService<IOptions<SecurePlaybackOptions>>(),
            sp.GetRequiredService<ISecureMediaWorker>(),
            sp.GetRequiredService<IProtectedMediaStorage>()));
        services.AddScoped<ISecurityEventService>(sp => new SecurityEventService(
            sp.GetRequiredService<AppDbContext>(),
            sp.GetRequiredService<ISystemClock>(),
            sp.GetRequiredService<IBunnyOptionsProvider>(),
            sp.GetRequiredService<IVideoSecurityPolicyService>(),
            sp.GetRequiredService<SecurityMetrics>()));
        services.AddScoped<IAuditLogService, AuditLogService>();

        services.AddHostedService<PolicySeederHostedService>();

        services.AddHealthChecks()
            .AddCheck<AppMigrationHealthCheck>("migrations", tags: new[] { "ready" });

        return services;
    }

}
