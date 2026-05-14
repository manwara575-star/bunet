using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Route("api/webhooks/bunny/stream")]
[Microsoft.AspNetCore.Mvc.IgnoreAntiforgeryToken]
public sealed class BunnyWebhookController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IBunnyOptionsProvider _options;
    private readonly ILogger<BunnyWebhookController> _log;

    public BunnyWebhookController(AppDbContext db, IBunnyOptionsProvider options, ILogger<BunnyWebhookController> log)
    {
        _db = db;
        _options = options;
        _log = log;
    }

    public sealed record Payload(string? VideoLibraryId, string? VideoGuid, int? Status);

    [HttpPost]
    [RequestSizeLimit(64 * 1024)]
    public async Task<ActionResult> Post(CancellationToken ct)
    {
        using var reader = new StreamReader(Request.Body, Encoding.UTF8);
        var rawBody = await reader.ReadToEndAsync(ct);
        var opts = await _options.GetAsync(ct);

        if (!VerifyWebhook(rawBody, opts))
        {
            _log.LogWarning("Bunny webhook rejected: bad/missing signature or secret header");
            return Unauthorized();
        }

        var payload = JsonSerializer.Deserialize<Payload>(rawBody, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (payload is null || string.IsNullOrEmpty(payload.VideoGuid)) return BadRequest();
        if (!LibraryMatches(payload.VideoLibraryId, opts))
        {
            _log.LogWarning("Bunny webhook rejected: library mismatch {LibraryId}", payload.VideoLibraryId);
            return BadRequest("VideoLibraryId does not match configured Bunny library.");
        }

        // Event-id-based idempotency on top of the body-hash receipt below. Bunny's webhook
        // may retry with a slightly different payload (e.g. timestamp tweaks) but the same
        // logical event; we de-dupe by an explicit header when present, otherwise synthesize
        // a stable id from (VideoGuid, Status, day) so retries within the dedupe window
        // collapse to one logical event.
        var now = DateTimeOffset.UtcNow;
        var eventId = ResolveEventId(payload, now);
        var truncatedPayload = rawBody.Length > 8 * 1024 ? rawBody[..(8 * 1024)] : rawBody;

        var bodyHash = Sha256Hex(rawBody);
        if (!await _db.BunnyWebhookReceipts.AnyAsync(r => r.BodyHash == bodyHash, ct))
        {
            _db.BunnyWebhookReceipts.Add(new BunnyWebhookReceipt
            {
                BodyHash = bodyHash,
                SignatureHash = Sha256Hex(EffectiveSignatureForReceipt()),
                VideoGuid = payload.VideoGuid,
                Status = payload.Status,
                ReceivedAt = now
            });
            try
            {
                await _db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException ex) when (IsUniqueViolation(ex))
            {
                _log.LogInformation("Concurrent duplicate Bunny webhook receipt for {Guid}", payload.VideoGuid);
            }
        }

        var video = await _db.Videos.FirstOrDefaultAsync(v => v.BunnyVideoId == payload.VideoGuid, ct);
        if (video is null)
        {
            _log.LogInformation("Webhook for unknown video {Guid}", payload.VideoGuid);
            return Accepted();
        }

        var evt = await _db.WebhookEvents.FirstOrDefaultAsync(e => e.EventId == eventId, ct);
        if (evt?.ProcessedAt is not null)
        {
            _log.LogInformation("Ignoring processed Bunny webhook event replay {EventId} for {Guid}", eventId, payload.VideoGuid);
            return Accepted();
        }

        if (evt is null)
        {
            evt = new WebhookEvent
            {
                EventId = eventId,
                VideoGuid = payload.VideoGuid,
                Status = payload.Status,
                RawPayload = truncatedPayload,
                ReceivedAt = now,
                Attempts = 1
            };
            _db.WebhookEvents.Add(evt);
            try
            {
                await _db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException ex) when (IsUniqueViolation(ex))
            {
                evt = await _db.WebhookEvents.FirstAsync(e => e.EventId == eventId, ct);
                if (evt.ProcessedAt is not null)
                {
                    _log.LogInformation("Ignoring concurrently processed Bunny webhook event {EventId}", eventId);
                    return Accepted();
                }
                evt.Attempts += 1;
                evt.RawPayload = truncatedPayload;
                evt.ReceivedAt = now;
                evt.LastError = null;
                await _db.SaveChangesAsync(ct);
            }
        }
        else
        {
            evt.Attempts += 1;
            evt.RawPayload = truncatedPayload;
            evt.ReceivedAt = now;
            evt.LastError = null;
            await _db.SaveChangesAsync(ct);
        }

        if (payload.Status is int s)
        {
            var newStatus = MapStatus(s);
            try
            {
                if (AllowsTransition(video.Status, newStatus))
                {
                    video.Status = newStatus;
                    video.UpdatedAt = DateTimeOffset.UtcNow;
                    await _db.SaveChangesAsync(ct);
                }
                else
                {
                    _log.LogWarning("Ignoring webhook status regression for {Guid}: {Old} -> {New}", payload.VideoGuid, video.Status, newStatus);
                }

                evt.ProcessedAt = DateTimeOffset.UtcNow;
                await _db.SaveChangesAsync(ct);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to apply webhook status update for {Guid} (event {EventId})", payload.VideoGuid, eventId);
                evt.LastError = Truncate(ex.Message, 1024);
                try { await _db.SaveChangesAsync(ct); } catch (Exception ex2) { _log.LogWarning(ex2, "Best-effort persistence of webhook failure metadata for event {EventId}", eventId); }
                // Return 500 so Bunny retries; unprocessed EventId rows are retried above.
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }
        else
        {
            evt.ProcessedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(ct);
        }
        return Accepted();
    }

    private string ResolveEventId(Payload payload, DateTimeOffset receivedAt)
    {
        var headerId = Request.Headers["X-BunnyStream-Event-Id"].ToString();
        if (!string.IsNullOrWhiteSpace(headerId))
            return headerId.Trim();

        // Synthesized fallback: stable per (video, status, UTC day). The day bucket keeps the
        // dedupe window bounded so a status that legitimately reoccurs on a later day is not
        // suppressed forever.
        var day = receivedAt.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        return "syn:" + Sha256Hex($"{payload.VideoGuid}:{payload.Status?.ToString(CultureInfo.InvariantCulture) ?? "_"}:{day}");
    }

    private static string Truncate(string value, int max) =>
        string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..max];

    private static VideoStatus MapStatus(int code) => code switch
    {
        0 => VideoStatus.Created,
        1 or 2 or 3 => VideoStatus.Processing,
        4 => VideoStatus.Ready,
        5 or 6 or 7 or 8 => VideoStatus.Failed,
        _ => VideoStatus.Processing
    };

    private string EffectiveSignatureForReceipt()
    {
        var bunnySig = Request.Headers["X-BunnyStream-Signature"].ToString();
        if (!string.IsNullOrWhiteSpace(bunnySig)) return NormalizeSignature(bunnySig);
        return Request.Headers["X-Bunny-Webhook-Secret"].ToString();
    }

    private bool VerifyWebhook(string rawBody, BunnyOptions opts)
    {
        var bunnySig = Request.Headers["X-BunnyStream-Signature"].ToString();
        if (!string.IsNullOrWhiteSpace(bunnySig))
        {
            var version = Request.Headers["X-BunnyStream-Signature-Version"].ToString();
            var alg = Request.Headers["X-BunnyStream-Signature-Algorithm"].ToString();
            if (!string.Equals(version, "v1", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(alg, "hmac-sha256", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(opts.ApiKey))
                return false;

            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(opts.ApiKey));
            var expected = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(rawBody))).ToLowerInvariant();
            return CryptographicEquals(NormalizeSignature(bunnySig), expected);
        }

        if (string.IsNullOrWhiteSpace(opts.WebhookSecret)) return false;
        var provided = Request.Headers["X-Bunny-Webhook-Secret"].ToString();
        return CryptographicEquals(provided, opts.WebhookSecret);
    }

    private static bool LibraryMatches(string? libraryId, BunnyOptions opts) =>
        long.TryParse(libraryId, out var parsed) && parsed == opts.LibraryId;

    private static bool AllowsTransition(VideoStatus current, VideoStatus next)
    {
        if (current == VideoStatus.Deleted) return false;
        return StatusRank(next) >= StatusRank(current);
    }

    private static int StatusRank(VideoStatus status) => status switch
    {
        VideoStatus.Created => 0,
        VideoStatus.Uploading => 1,
        VideoStatus.Processing => 2,
        VideoStatus.Failed => 3,
        VideoStatus.Ready => 4,
        VideoStatus.Deleted => 5,
        _ => 0
    };

    private static string NormalizeSignature(string signature)
    {
        const string prefix = "sha256=";
        signature = signature.Trim();
        return signature.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? signature[prefix.Length..]
            : signature;
    }

    private static string Sha256Hex(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();

    private static bool IsUniqueViolation(DbUpdateException ex) =>
        ex.InnerException?.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase) == true;

    // Constant-time comparison to avoid timing leaks on the webhook secret.
    private static bool CryptographicEquals(string a, string b)
    {
        if (a is null || b is null) return false;
        var aa = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return aa.Length == bb.Length && CryptographicOperations.FixedTimeEquals(aa, bb);
    }
}
