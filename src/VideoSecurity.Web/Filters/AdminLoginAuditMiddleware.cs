using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Filters;

/// <summary>
/// Detects fresh sign-ins (auth ticket IssuedUtc within the last 30s) for users in any
/// admin-tier role and writes a single <see cref="AuditAction.AdminLogin"/> row.
///
/// Idempotency: keyed in <see cref="IMemoryCache"/> by (userId|issuedUtcTicks). The cache
/// entry lives slightly longer than the freshness window so repeated requests on the same
/// cookie do not produce duplicate audit rows.
///
/// Operational note: the cache is process-local. After a restart the first authenticated
/// request from each admin user will produce a single audit row even if the cookie was
/// issued before the restart, because IssuedUtc may still fall inside the 30s window.
/// This is intentional: we accept up to one extra audit per cookie per process to keep
/// the implementation simple and dependency-free.
/// </summary>
public sealed class AdminLoginAuditMiddleware
{
    // Keep slightly larger than FreshSignInWindow so the idempotency entry outlives any
    // burst of requests that share the same auth ticket.
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FreshSignInWindow = TimeSpan.FromSeconds(30);

    private static readonly string[] AdminRoles =
    {
        IdentitySeeder.AdminRole,
        IdentitySeeder.SuperAdminRole,
        IdentitySeeder.VideoAdminRole,
        IdentitySeeder.SecurityAuditorRole,
        IdentitySeeder.SupportAgentRole
    };

    private readonly RequestDelegate _next;

    public AdminLoginAuditMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(
        HttpContext ctx,
        IMemoryCache cache,
        IAuditLogService audit,
        IBunnyOptionsProvider options)
    {
        try
        {
            var user = ctx.User;
            if (user?.Identity is { IsAuthenticated: true } &&
                AdminRoles.Any(r => user.IsInRole(r)))
            {
                var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (!string.IsNullOrEmpty(userId))
                {
                    // Read the already-completed authentication result captured by
                    // UseAuthentication; do NOT re-invoke the authentication scheme here.
                    var feature = ctx.Features.Get<IAuthenticateResultFeature>();
                    var result = feature?.AuthenticateResult;
                    var issuedUtc = result?.Properties?.IssuedUtc;
                    if (issuedUtc is not null &&
                        DateTimeOffset.UtcNow - issuedUtc.Value <= FreshSignInWindow)
                    {
                        var key = "adminlogin:" + Hash(userId + "|" + issuedUtc.Value.UtcTicks.ToString());
                        if (!cache.TryGetValue(key, out _))
                        {
                            cache.Set(key, true, CacheTtl);
                            var opts = await options.GetAsync(ctx.RequestAborted);
                            await audit.WriteAsync(
                                userId,
                                AuditAction.AdminLogin,
                                "User",
                                userId,
                                new { issuedUtc = issuedUtc.Value, scheme = result?.Ticket?.AuthenticationScheme },
                                AuditHashing.HashIp(opts, ctx),
                                AuditHashing.HashUa(opts, ctx),
                                ctx.RequestAborted);
                        }
                    }
                }
            }
        }
        catch
        {
            // Audit must never break the request.
        }

        await _next(ctx);
    }

    private static string Hash(string input)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }
}
