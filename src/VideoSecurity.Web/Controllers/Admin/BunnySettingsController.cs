using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Controllers.Admin;

[Authorize(Policy = "SuperAdminOnly")]
public sealed class BunnySettingsController : Controller
{
    private readonly IBunnyOptionsProvider _options;
    private readonly AppDbContext _db;
    private readonly IAuditLogService _audit;

    public BunnySettingsController(IBunnyOptionsProvider options, AppDbContext db, IAuditLogService audit)
    {
        _options = options;
        _db = db;
        _audit = audit;
    }

    [HttpGet("/admin/bunny")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var options = await _options.GetAsync(ct);
        var settings = await _db.BunnyRuntimeSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
        return View(BunnySettingsViewModel.From(options, settings, _options.Validate(options)));
    }

    [HttpPost("/admin/bunny")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(BunnySettingsViewModel model, CancellationToken ct)
    {
        var current = await _options.GetAsync(ct);
        var next = model.ToOptions(current);
        var failures = _options.Validate(next);
        foreach (var failure in failures)
            ModelState.AddModelError(string.Empty, failure);

        if (!ModelState.IsValid)
        {
            var settings = await _db.BunnyRuntimeSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
            model.ApplyStatus(next, settings, failures);
            model.ClearSecretInputs();
            return View("Index", model);
        }

        var actor = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
        await _options.SaveAsync(next, actor, ct);
        var saved = await _options.GetAsync(ct);
        await _audit.WriteAsync(
            actor,
            AuditAction.Other,
            "BunnyRuntimeSettings",
            "1",
            new
            {
                saved.LibraryId,
                saved.CdnHostname,
                saved.ApiBaseUrl,
                saved.TusEndpoint,
                saved.EmbedBaseUrl,
                saved.DefaultSessionTtl,
                saved.DefaultUploadTtl,
                saved.LockSessionToIp,
                saved.AssumedUploadBytesPerSecond,
                saved.WebhookEventDedupeWindow,
                changedSecrets = model.ChangedSecretNames()
            },
            AuditHashing.HashIp(saved, HttpContext),
            AuditHashing.HashUa(saved, HttpContext),
            ct);

        TempData["BunnySettingsMessage"] = "Bunny settings saved. New API calls, uploads, webhooks, and playback tokens will use them immediately.";
        return RedirectToAction(nameof(Index));
    }

    public sealed class BunnySettingsViewModel
    {
        [Range(1, long.MaxValue)] public long LibraryId { get; set; }
        [Display(Name = "API key")] public string? ApiKey { get; set; }
        [Display(Name = "Embed token key")] public string? EmbedTokenKey { get; set; }
        [Required, StringLength(255)] public string CdnHostname { get; set; } = string.Empty;
        [Display(Name = "CDN token key")] public string? CdnTokenKey { get; set; }
        public bool ClearCdnTokenKey { get; set; }
        [Required, Url] public string ApiBaseUrl { get; set; } = "https://video.bunnycdn.com";
        [Required, Url] public string TusEndpoint { get; set; } = "https://video.bunnycdn.com/tusupload";
        [Required, Url] public string EmbedBaseUrl { get; set; } = "https://iframe.mediadelivery.net";
        [Range(1, 120)] public int DefaultSessionTtlMinutes { get; set; } = 15;
        [Range(1, 10080)] public int DefaultUploadTtlMinutes { get; set; } = 240;
        public bool LockSessionToIp { get; set; }
        [Display(Name = "Privacy hash pepper")] public string? PrivacyHashPepper { get; set; }
        public bool ClearPrivacyHashPepper { get; set; }
        [Display(Name = "Webhook secret")] public string? WebhookSecret { get; set; }
        public bool ClearWebhookSecret { get; set; }
        [Range(1, int.MaxValue)] public int AssumedUploadBytesPerSecond { get; set; } = 1_500_000;
        [Range(1, 720)] public int WebhookEventDedupeWindowHours { get; set; } = 24;
        public bool HasApiKey { get; set; }
        public bool HasEmbedTokenKey { get; set; }
        public bool HasCdnTokenKey { get; set; }
        public bool HasPrivacyHashPepper { get; set; }
        public bool HasWebhookSecret { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public string? UpdatedByUserId { get; set; }
        public IReadOnlyList<string> ValidationFailures { get; set; } = Array.Empty<string>();

        public static BunnySettingsViewModel From(BunnyOptions options, BunnyRuntimeSettings? settings, IReadOnlyList<string> failures)
        {
            var model = new BunnySettingsViewModel
            {
                LibraryId = options.LibraryId,
                CdnHostname = options.CdnHostname,
                ApiBaseUrl = options.ApiBaseUrl,
                TusEndpoint = options.TusEndpoint,
                EmbedBaseUrl = options.EmbedBaseUrl,
                DefaultSessionTtlMinutes = Math.Max(1, (int)Math.Round(options.DefaultSessionTtl.TotalMinutes)),
                DefaultUploadTtlMinutes = Math.Max(1, (int)Math.Round(options.DefaultUploadTtl.TotalMinutes)),
                LockSessionToIp = options.LockSessionToIp,
                AssumedUploadBytesPerSecond = options.AssumedUploadBytesPerSecond,
                WebhookEventDedupeWindowHours = Math.Max(1, (int)Math.Round(options.WebhookEventDedupeWindow.TotalHours)),
                UpdatedAt = settings?.UpdatedAt,
                UpdatedByUserId = settings?.UpdatedByUserId
            };
            model.ApplyStatus(options, settings, failures);
            return model;
        }

        public BunnyOptions ToOptions(BunnyOptions current) => new()
        {
            LibraryId = LibraryId,
            ApiKey = string.IsNullOrWhiteSpace(ApiKey) ? current.ApiKey : ApiKey.Trim(),
            EmbedTokenKey = string.IsNullOrWhiteSpace(EmbedTokenKey) ? current.EmbedTokenKey : EmbedTokenKey.Trim(),
            CdnHostname = CdnHostname.Trim(),
            CdnTokenKey = ClearCdnTokenKey ? null : string.IsNullOrWhiteSpace(CdnTokenKey) ? current.CdnTokenKey : CdnTokenKey.Trim(),
            ApiBaseUrl = ApiBaseUrl.Trim().TrimEnd('/'),
            TusEndpoint = TusEndpoint.Trim(),
            EmbedBaseUrl = EmbedBaseUrl.Trim().TrimEnd('/'),
            DefaultSessionTtl = TimeSpan.FromMinutes(DefaultSessionTtlMinutes),
            DefaultUploadTtl = TimeSpan.FromMinutes(DefaultUploadTtlMinutes),
            LockSessionToIp = LockSessionToIp,
            PrivacyHashPepper = ClearPrivacyHashPepper ? null : string.IsNullOrWhiteSpace(PrivacyHashPepper) ? current.PrivacyHashPepper : PrivacyHashPepper.Trim(),
            WebhookSecret = ClearWebhookSecret ? null : string.IsNullOrWhiteSpace(WebhookSecret) ? current.WebhookSecret : WebhookSecret.Trim(),
            AssumedUploadBytesPerSecond = AssumedUploadBytesPerSecond,
            WebhookEventDedupeWindow = TimeSpan.FromHours(WebhookEventDedupeWindowHours)
        };

        public void ApplyStatus(BunnyOptions options, BunnyRuntimeSettings? settings, IReadOnlyList<string> failures)
        {
            HasApiKey = !string.IsNullOrWhiteSpace(options.ApiKey);
            HasEmbedTokenKey = !string.IsNullOrWhiteSpace(options.EmbedTokenKey);
            HasCdnTokenKey = !string.IsNullOrWhiteSpace(options.CdnTokenKey);
            HasPrivacyHashPepper = !string.IsNullOrWhiteSpace(options.PrivacyHashPepper);
            HasWebhookSecret = !string.IsNullOrWhiteSpace(options.WebhookSecret);
            UpdatedAt = settings?.UpdatedAt;
            UpdatedByUserId = settings?.UpdatedByUserId;
            ValidationFailures = failures;
        }

        public string[] ChangedSecretNames()
        {
            var names = new List<string>();
            if (!string.IsNullOrWhiteSpace(ApiKey)) names.Add(nameof(ApiKey));
            if (!string.IsNullOrWhiteSpace(EmbedTokenKey)) names.Add(nameof(EmbedTokenKey));
            if (!string.IsNullOrWhiteSpace(CdnTokenKey) || ClearCdnTokenKey) names.Add(nameof(CdnTokenKey));
            if (!string.IsNullOrWhiteSpace(PrivacyHashPepper) || ClearPrivacyHashPepper) names.Add(nameof(PrivacyHashPepper));
            if (!string.IsNullOrWhiteSpace(WebhookSecret) || ClearWebhookSecret) names.Add(nameof(WebhookSecret));
            return names.ToArray();
        }

        public void ClearSecretInputs()
        {
            ApiKey = null;
            EmbedTokenKey = null;
            CdnTokenKey = null;
            PrivacyHashPepper = null;
            WebhookSecret = null;
        }
    }
}