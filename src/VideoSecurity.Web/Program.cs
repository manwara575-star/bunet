using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System.Threading.RateLimiting;
using VideoSecurity.Infrastructure;
using VideoSecurity.Infrastructure.Observability;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web;
using VideoSecurity.Web.Filters;
using VideoSecurity.Web.HostedServices;
using VideoSecurity.Web.Middleware;
using VideoSecurity.Web.Services;

var builder = WebApplication.CreateBuilder(args);
var cookieSecurePolicy = builder.Configuration.GetValue<bool>("Hosting:AllowInsecureCookies")
    ? CookieSecurePolicy.SameAsRequest
    : CookieSecurePolicy.Always;

builder.Services.AddVideoSecurityInfrastructure(builder.Configuration);
builder.Services.AddDataProtection();

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(o =>
    {
        o.Password.RequireDigit = true;
        o.Password.RequiredLength = 12;
        o.Password.RequireNonAlphanumeric = false;
        o.SignIn.RequireConfirmedAccount = false;
        o.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders()
    .AddDefaultUI();

builder.Services.AddControllersWithViews(o =>
{
    o.Filters.Add(new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute());
});
builder.Services.AddRazorPages();
builder.Services.AddAntiforgery(o =>
{
    o.HeaderName = "RequestVerificationToken";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = cookieSecurePolicy;
});
builder.Services.AddProblemDetails();

// Health checks: liveness (no deps) + readiness (db).
var connStr = builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=videosecurity.db";
builder.Services.AddHealthChecks()
    .AddSqlite(connStr, name: "sqlite", tags: new[] { "ready" });

// Rate limiting: protects anonymous + heartbeat endpoints from flood / replay abuse.
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("anon-events", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
    o.AddPolicy("heartbeat", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                          ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
    o.AddPolicy("session-create", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                          ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(5),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

// Background cleanup of expired playback sessions + stale telemetry.
builder.Services.AddHostedService<ExpiredSessionCleanupService>();
builder.Services.AddScoped<AuditLogger>();

builder.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/Identity/Account/Login";
    o.AccessDeniedPath = "/Identity/Account/AccessDenied";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = cookieSecurePolicy;
});

builder.Services.AddAuthorization(o =>
{
    // Existing AdminOnly policy: legacy SuperAdmin alias OR new Admin (super-admin) role.
    o.AddPolicy("AdminOnly", p => p.RequireRole(IdentitySeeder.AdminRole, IdentitySeeder.SuperAdminRole));
    // SuperAdmin == Admin role.
    o.AddPolicy("SuperAdminOnly", p => p.RequireRole(IdentitySeeder.AdminRole, IdentitySeeder.SuperAdminRole));
    o.AddPolicy("VideoAdminOnly", p => p.RequireRole(IdentitySeeder.AdminRole, IdentitySeeder.SuperAdminRole, IdentitySeeder.VideoAdminRole));
    o.AddPolicy("SecurityAuditorOnly", p => p.RequireRole(IdentitySeeder.AdminRole, IdentitySeeder.SuperAdminRole, IdentitySeeder.SecurityAuditorRole));
    o.AddPolicy("SupportAgentOnly", p => p.RequireRole(IdentitySeeder.AdminRole, IdentitySeeder.SuperAdminRole, IdentitySeeder.SupportAgentRole));
    o.AddPolicy("MetricsOnly", p => p.RequireRole(IdentitySeeder.AdminRole, IdentitySeeder.SuperAdminRole));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("VideoSecurity.Web"))
    .WithTracing(t =>
    {
        t.AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddSource("VideoSecurity");
        if (!builder.Environment.IsProduction()) t.AddConsoleExporter();
    })
    .WithMetrics(m =>
    {
        m.AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddMeter(VideoSecurityMetrics.MeterName)
            .AddMeter(SecurityMetrics.MeterName)
            .AddPrometheusExporter();
        if (!builder.Environment.IsProduction()) m.AddConsoleExporter();
    });

builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders =
        Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
        Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.MigrateAsync();
    await IdentitySeeder.SeedAsync(scope.ServiceProvider, app.Configuration);
}

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseForwardedHeaders();
if (!app.Configuration.GetValue<bool>("Hosting:DisableHttpsRedirection"))
    app.UseHttpsRedirection();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseMiddleware<AdminLoginAuditMiddleware>();
app.UseRateLimiter();
app.UseAuthorization();

var metricsEndpoint = app.MapPrometheusScrapingEndpoint("/metrics");
if (app.Configuration.GetValue<bool>("Metrics:AllowAnonymous"))
    metricsEndpoint.AllowAnonymous();
else
    metricsEndpoint.RequireAuthorization("MetricsOnly");

app.MapHealthChecks("/health/live", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = _ => false  // liveness: no checks, just "process is up"
});
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = c => c.Tags.Contains("ready")
});

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();

public partial class Program { }
