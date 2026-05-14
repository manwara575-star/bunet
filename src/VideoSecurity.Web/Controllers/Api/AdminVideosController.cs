using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;
using VideoSecurity.Web.Services;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Route("api/admin/videos")]
[Authorize(Policy = "AdminOnly")]
public sealed class AdminVideosController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IBunnyStreamClient _bunny;
    private readonly IBunnyTusUploadSigner _tus;
    private readonly IBunnyOptionsProvider _options;
    private readonly IAuditLogService _audit;
    private readonly ILogger<AdminVideosController> _logger;

    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".mp4", ".mkv", ".mov", ".avi", ".webm" };
    private const long DefaultMaxFileSizeBytes = 10L * 1024 * 1024 * 1024; // 10 GB

    public AdminVideosController(AppDbContext db, IBunnyStreamClient bunny, IBunnyTusUploadSigner tus,
        IBunnyOptionsProvider options, IAuditLogService audit, ILogger<AdminVideosController> logger)
    {
        _db = db;
        _bunny = bunny;
        _tus = tus;
        _options = options;
        _audit = audit;
        _logger = logger;
    }

    public sealed record CreateVideoRequest(
        [Required, StringLength(512, MinimumLength = 1)] string Title,
        string? Description,
        string? CourseId,
        string? CollectionId,
        [Required, StringLength(256)] string FileName,
        [Range(1, long.MaxValue)] long? FileSizeBytes = null);

    public sealed record CreateVideoResponse(
        Guid VideoId,
        string BunnyVideoId,
        long LibraryId,
        BunnyTusUploadCredentials Upload);

    [HttpPost]
    public async Task<ActionResult<CreateVideoResponse>> Create([FromBody] CreateVideoRequest req, CancellationToken ct)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        // Upload validation: extension allowlist + file size limit
        var ext = Path.GetExtension(req.FileName);
        if (string.IsNullOrEmpty(ext) || !AllowedExtensions.Contains(ext))
        {
            ModelState.AddModelError(nameof(req.FileName),
                $"File type '{ext}' is not allowed. Accepted: {string.Join(", ", AllowedExtensions)}");
            return ValidationProblem(ModelState);
        }
        if (req.FileSizeBytes.HasValue && req.FileSizeBytes.Value > DefaultMaxFileSizeBytes)
        {
            ModelState.AddModelError(nameof(req.FileSizeBytes),
                $"File size exceeds maximum of {DefaultMaxFileSizeBytes / (1024 * 1024 * 1024)} GB.");
            return ValidationProblem(ModelState);
        }

        var opts = await _options.GetAsync(ct);
        var failures = _options.Validate(opts);
        if (failures.Count > 0) return Problem(string.Join(" ", failures), statusCode: StatusCodes.Status400BadRequest);

        var bunny = await _bunny.CreateVideoAsync(req.Title, req.CollectionId, ct);

        var entity = new Video
        {
            Title = req.Title,
            Description = req.Description,
            CourseId = req.CourseId,
            BunnyCollectionId = req.CollectionId,
            BunnyLibraryId = bunny.LibraryId,
            BunnyVideoId = bunny.Guid,
            Status = VideoStatus.Uploading,
            CreatedByUserId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? string.Empty
        };
        _db.Videos.Add(entity);
        await _db.SaveChangesAsync(ct);
        await _audit.WriteAsync(
            User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "system",
            AuditAction.VideoCreated,
            nameof(Video),
            entity.Id.ToString(),
            new { entity.Title, entity.BunnyVideoId },
            AuditHashing.HashIp(opts, HttpContext),
            AuditHashing.HashUa(opts, HttpContext),
            ct);

        var creds = _tus.CreateCredentials(entity.BunnyVideoId, req.FileName, opts.DefaultUploadTtl, req.FileSizeBytes);
        return Ok(new CreateVideoResponse(entity.Id, entity.BunnyVideoId, entity.BunnyLibraryId, creds));
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult> Get(Guid id, CancellationToken ct)
    {
        var v = await _db.Videos.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (v is null) return NotFound();

        try
        {
            var info = await _bunny.GetVideoAsync(v.BunnyVideoId, ct);
            var newStatus = MapBunnyStatus(info.Status);
            if (newStatus != v.Status || Math.Abs(info.Length - v.DurationSeconds) > 0.01)
            {
                var tracked = await _db.Videos.FirstAsync(x => x.Id == id, ct);
                tracked.Status = newStatus;
                tracked.DurationSeconds = info.Length;
                tracked.UpdatedAt = DateTimeOffset.UtcNow;
                await _db.SaveChangesAsync(ct);
                v = tracked;
            }
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Best-effort Bunny status refresh failed for video {VideoId}", id); }

        return Ok(new
        {
            v.Id,
            v.Title,
            v.Description,
            v.CourseId,
            v.Status,
            v.DurationSeconds,
            v.BunnyVideoId,
            v.BunnyLibraryId,
            v.CreatedAt,
            v.UpdatedAt
        });
    }

    [HttpGet]
    public async Task<ActionResult> List([FromQuery] int skip = 0, [FromQuery] int take = 50, CancellationToken ct = default)
    {
        take = Math.Clamp(take, 1, 200);
        var items = await _db.Videos.AsNoTracking()
            .Select(v => new { v.Id, v.Title, v.Status, v.DurationSeconds, v.CreatedAt, v.CourseId })
            .ToListAsync(ct);
        items = items.OrderByDescending(v => v.CreatedAt).Skip(skip).Take(take).ToList();
        return Ok(items);
    }

    [HttpDelete("{id:guid}")]
    public async Task<ActionResult> Delete(Guid id, CancellationToken ct)
    {
        var v = await _db.Videos.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (v is null) return NotFound();
        try { await _bunny.DeleteVideoAsync(v.BunnyVideoId, ct); }
        catch (Exception ex) { _logger.LogWarning(ex, "Best-effort Bunny delete failed for {BunnyVideoId}", v.BunnyVideoId); }
        v.Status = VideoStatus.Deleted;
        v.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);
        var opts = await _options.GetAsync(ct);
        await _audit.WriteAsync(
            User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "system",
            AuditAction.VideoDeleted,
            nameof(Video),
            v.Id.ToString(),
            new { v.BunnyVideoId },
            AuditHashing.HashIp(opts, HttpContext),
            AuditHashing.HashUa(opts, HttpContext),
            ct);
        return NoContent();
    }

    private static VideoStatus MapBunnyStatus(int code) => code switch
    {
        0 => VideoStatus.Created,
        1 or 2 or 3 => VideoStatus.Processing,
        4 => VideoStatus.Ready,
        5 or 6 => VideoStatus.Failed,
        _ => VideoStatus.Processing
    };
}
