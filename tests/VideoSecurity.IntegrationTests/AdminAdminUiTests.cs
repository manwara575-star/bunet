using System.Net;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web;

namespace VideoSecurity.IntegrationTests;

public sealed class AdminAdminUiTests : IClassFixture<BunnyMockFactory>
{
    private readonly BunnyMockFactory _baseline;
    public AdminAdminUiTests(BunnyMockFactory f) => _baseline = f;

    [Fact]
    public async Task Anonymous_GetPolicies_RedirectsOrUnauthorized()
    {
        var c = _baseline.CreateClient(new() { AllowAutoRedirect = false });
        var resp = await c.GetAsync("/admin/policies");
        ((int)resp.StatusCode).Should().BeOneOf(401, 302);
    }

    [Fact]
    public async Task Admin_RotateKey_InsertsNewVersionAndAuditRow()
    {
        await using var factory = AdminFactory();
        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var token = await GetAntiforgeryTokenAsync(client, "/admin/keys");

        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/keys/rotate")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["purpose"] = SigningKeyPurpose.EmbedToken.ToString(),
                ["notes"] = "test rotation"
            })
        };
        req.Headers.Add("RequestVerificationToken", token);
        var resp = await client.SendAsync(req);
        ((int)resp.StatusCode).Should().BeOneOf(200, 302);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var rows = await db.SigningKeyVersions
            .Where(k => k.Purpose == SigningKeyPurpose.EmbedToken)
            .OrderByDescending(k => k.Version)
            .ToListAsync();
        rows.Should().NotBeEmpty();
        rows.First().IsActive.Should().BeTrue();

        var audits = await db.AuditLogs.CountAsync(a => a.Action == AuditAction.KeyRotated);
        audits.Should().BeGreaterOrEqualTo(1);
    }

    [Fact]
    public async Task Admin_EditPolicy_UpdatesRowAndWritesAudit()
    {
        await using var factory = AdminFactory();

        Guid policyId;
        int originalTtl;
        VideoSensitivityTier tier;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            // PolicySeederHostedService should have inserted these; if not, seed one.
            var existing = await db.VideoSecurityPolicies.FirstOrDefaultAsync();
            if (existing is null)
            {
                existing = new VideoSecurityPolicy { Tier = VideoSensitivityTier.Standard };
                db.VideoSecurityPolicies.Add(existing);
                await db.SaveChangesAsync();
            }
            policyId = existing.Id;
            originalTtl = existing.EmbedTtlSeconds;
            tier = existing.Tier;
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var token = await GetAntiforgeryTokenAsync(client, $"/admin/policies/{policyId}/edit");

        var newTtl = originalTtl == 600 ? 720 : 600;
        var req = new HttpRequestMessage(HttpMethod.Post, $"/admin/policies/{policyId}/edit")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Id"] = policyId.ToString(),
                ["Tier"] = tier.ToString(),
                ["EmbedTtlSeconds"] = newTtl.ToString(),
                ["HeartbeatIntervalSeconds"] = "15",
                ["MaxConcurrentSessions"] = "2",
                ["AutoRevokeRiskThreshold"] = "80",
                ["RequireWatermark"] = "true",
                ["RevokeOnWatermarkTamper"] = "true"
            })
        };
        req.Headers.Add("RequestVerificationToken", token);
        var resp = await client.SendAsync(req);
        ((int)resp.StatusCode).Should().BeOneOf(200, 302);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var updated = await db.VideoSecurityPolicies.FirstAsync(p => p.Id == policyId);
            updated.EmbedTtlSeconds.Should().Be(newTtl);

            var audits = await db.AuditLogs.CountAsync(a =>
                a.Action == AuditAction.PolicyChanged && a.EntityId == policyId.ToString());
            audits.Should().BeGreaterOrEqualTo(1);
        }
    }

    [Fact]
    public async Task Admin_GrantRole_PutsUserInRoleAndWritesAudit()
    {
        await using var factory = AdminFactory();

        // Create a target user via the test factory's UserManager.
        string targetUserId;
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
            var email = $"target-{Guid.NewGuid():N}@test.local";
            var user = new ApplicationUser { UserName = email, Email = email, EmailConfirmed = true, DisplayName = "T" };
            var create = await users.CreateAsync(user, "TargetPass!12345");
            create.Succeeded.Should().BeTrue(string.Join("; ", create.Errors.Select(e => e.Description)));
            targetUserId = user.Id;
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("https://localhost");
        var token = await GetAntiforgeryTokenAsync(client, "/admin/roles");

        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/roles/grant")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userId"] = targetUserId,
                ["role"] = IdentitySeeder.SupportAgentRole
            })
        };
        req.Headers.Add("RequestVerificationToken", token);
        var resp = await client.SendAsync(req);
        ((int)resp.StatusCode).Should().BeOneOf(200, 302);

        using var verifyScope = factory.Services.CreateScope();
        var users2 = verifyScope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
        var u = await users2.FindByIdAsync(targetUserId);
        u.Should().NotBeNull();
        (await users2.IsInRoleAsync(u!, IdentitySeeder.SupportAgentRole)).Should().BeTrue();

        var db = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var audits = await db.AuditLogs.CountAsync(a =>
            a.Action == AuditAction.RoleChanged && a.EntityId == targetUserId);
        audits.Should().BeGreaterOrEqualTo(1);
    }

    [Fact]
    public async Task Admin_GetAuditLog_RendersOk()
    {
        await using var factory = AdminFactory();

        // Seed a known audit row so the page has something to render.
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.AuditLogs.Add(new AuditLog
            {
                ActorUserId = "seed-actor",
                Action = AuditAction.AdminLogin,
                EntityType = "User",
                EntityId = "seed-actor",
                MetadataJson = "{\"seeded\":true}",
                IpHash = "h",
                UserAgentHash = "h",
                CreatedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        var resp = await client.GetAsync("/admin/audit");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var html = await resp.Content.ReadAsStringAsync();
        html.Should().Contain("AdminLogin");
    }

    [Fact]
    public async Task Admin_GetAuditLog_FiltersSameDayRowsUsingUtcTickBounds()
    {
        await using var factory = AdminFactory();
        var actor = "audit-filter-" + Guid.NewGuid().ToString("N");
        var day = new DateTimeOffset(2026, 5, 14, 12, 0, 0, TimeSpan.Zero);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.AuditLogs.AddRange(
                new AuditLog
                {
                    ActorUserId = actor,
                    Action = AuditAction.AdminLogin,
                    EntityType = "User",
                    EntityId = "before",
                    MetadataJson = "before-bound",
                    IpHash = "h",
                    UserAgentHash = "h",
                    CreatedAt = day.AddMinutes(-5)
                },
                new AuditLog
                {
                    ActorUserId = actor,
                    Action = AuditAction.AdminLogin,
                    EntityType = "User",
                    EntityId = "inside",
                    MetadataJson = "inside-bound",
                    IpHash = "h",
                    UserAgentHash = "h",
                    CreatedAt = day.AddMinutes(5)
                },
                new AuditLog
                {
                    ActorUserId = actor,
                    Action = AuditAction.AdminLogin,
                    EntityType = "User",
                    EntityId = "after",
                    MetadataJson = "after-bound",
                    IpHash = "h",
                    UserAgentHash = "h",
                    CreatedAt = day.AddMinutes(20)
                });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        var from = Uri.EscapeDataString(day.ToString("O"));
        var to = Uri.EscapeDataString(day.AddMinutes(10).ToString("O"));
        var resp = await client.GetAsync($"/admin/audit?actor={actor}&from={from}&to={to}");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var html = await resp.Content.ReadAsStringAsync();
        html.Should().Contain("inside-bound");
        html.Should().NotContain("before-bound");
        html.Should().NotContain("after-bound");
    }

    private WebApplicationFactoryForTests AdminFactory()
    {
        var f = _baseline.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureTestServices(services =>
            {
                services.AddAuthentication(TestAuthHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
                services.Configure<AuthenticationOptions>(o =>
                {
                    o.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                    o.DefaultChallengeScheme = TestAuthHandler.SchemeName;
                    o.DefaultScheme = TestAuthHandler.SchemeName;
                });
            });
        });
        return new WebApplicationFactoryForTests(f);
    }

    private static async Task<string> GetAntiforgeryTokenAsync(HttpClient client, string path)
    {
        var page = await client.GetAsync(path);
        page.EnsureSuccessStatusCode();
        var html = await page.Content.ReadAsStringAsync();
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"");
        match.Success.Should().BeTrue($"page {path} must render an antiforgery token");
        return match.Groups["token"].Value;
    }

    // Thin wrapper so we can `await using` and dispose without disposing the shared fixture factory.
    private sealed class WebApplicationFactoryForTests : IAsyncDisposable
    {
        private readonly Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> _inner;
        public WebApplicationFactoryForTests(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> inner) => _inner = inner;
        public IServiceProvider Services => _inner.Services;
        public HttpClient CreateClient(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions o) => _inner.CreateClient(o);
        public ValueTask DisposeAsync() { _inner.Dispose(); return ValueTask.CompletedTask; }
    }
}
