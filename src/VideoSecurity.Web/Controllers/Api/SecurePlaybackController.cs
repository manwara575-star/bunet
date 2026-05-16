using System.Net.Http.Headers;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Persistence;

namespace VideoSecurity.Web.Controllers.Api;

[ApiController]
[Route("api/secure-playback")]
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public sealed class SecurePlaybackController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IProtectedMediaStorage _storage;
    private readonly ISecureMediaWorker _worker;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly SecurePlaybackOptions _options;

    public SecurePlaybackController(
        AppDbContext db,
        IProtectedMediaStorage storage,
        ISecureMediaWorker worker,
        IHttpClientFactory httpClientFactory,
        IOptions<SecurePlaybackOptions> options)
    {
        _db = db;
        _storage = storage;
        _worker = worker;
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
    }

    [HttpPost("{sessionId:guid}/offer")]
    [EnableRateLimiting("secure-playback")]
    [RequestSizeLimit(128 * 1024)]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<ActionResult<SecurePlaybackAnswerResponse>> Offer(
        Guid sessionId,
        [FromBody] SecurePlaybackOfferRequest request,
        CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store, private";
        Response.Headers.Pragma = "no-cache";

        if (!string.Equals(request.Type, "offer", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(request.Sdp))
        {
            return BadRequest(new { error = "A WebRTC SDP offer is required." });
        }

        var validation = await ValidateSessionAsync(
            sessionId,
            Request.Headers["X-Playback-Session-Token"].ToString(),
            requireSource: true,
            ct);
        if (validation.Error is not null) return validation.Error;
        var session = validation.Session!;
        var video = validation.Video!;

        if (!_options.Enabled || string.IsNullOrWhiteSpace(_options.WhepEndpointTemplate))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new
            {
                error = "Secure WebRTC worker is not configured.",
                detail = "Configure SecurePlayback:WhepEndpointTemplate to a WHEP-compatible media worker."
            });
        }

        if (!TryBuildEndpoint(_options.WhepEndpointTemplate, session, video, out var endpoint))
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "Secure WebRTC worker endpoint is invalid." });
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.OfferTimeout);

        var client = _httpClientFactory.CreateClient();
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            try
            {
                using var upstream = new HttpRequestMessage(HttpMethod.Post, endpoint)
                {
                    Content = new StringContent(request.Sdp, Encoding.UTF8, "application/sdp")
                };
                upstream.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/sdp"));
                if (!string.IsNullOrWhiteSpace(_options.WhepBearerToken))
                    upstream.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.WhepBearerToken);

                using var answer = await client.SendAsync(upstream, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                var answerSdp = await answer.Content.ReadAsStringAsync(timeout.Token);
                if (answer.IsSuccessStatusCode)
                    return Ok(new SecurePlaybackAnswerResponse("answer", answerSdp));

                if (attempt == 5 || !IsTransientWorkerStartupStatus(answer.StatusCode))
                    return StatusCode((int)answer.StatusCode, new { error = "Secure WebRTC worker rejected the offer." });
            }
            catch (HttpRequestException) when (attempt < 5)
            {
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested && attempt < 5)
            {
            }
            catch (HttpRequestException)
            {
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "Secure WebRTC worker is unavailable." });
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "Secure WebRTC worker timed out." });
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), timeout.Token);
        }

        return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "Secure WebRTC worker rejected the offer." });
    }

    [HttpPost("{sessionId:guid}/seek")]
    [EnableRateLimiting("secure-playback")]
    [RequestSizeLimit(8 * 1024)]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<ActionResult<SecurePlaybackSeekResponse>> Seek(
        Guid sessionId,
        [FromBody] SecurePlaybackSeekRequest request,
        CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store, private";
        Response.Headers.Pragma = "no-cache";

        var validation = await ValidateSessionAsync(
            sessionId,
            Request.Headers["X-Playback-Session-Token"].ToStringOrFallback(request.HeartbeatToken),
            requireSource: true,
            ct);
        if (validation.Error is not null) return validation.Error;

        var session = validation.Session!;
        var video = validation.Video!;
        var duration = video.DurationSeconds > 0 ? video.DurationSeconds : double.PositiveInfinity;
        var position = Math.Clamp(
            double.IsFinite(request.PositionSeconds) ? request.PositionSeconds : 0,
            0,
            double.IsPositiveInfinity(duration) ? double.MaxValue : Math.Max(0, duration - 1));

        await _worker.SeekAsync(session, video, TimeSpan.FromSeconds(position), ct);
        session.LastKnownPositionSeconds = position;
        session.LastHeartbeatAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        return Ok(new SecurePlaybackSeekResponse(position, $"/api/secure-playback/{session.Id}/offer"));
    }

    [HttpPost("{sessionId:guid}/close")]
    [EnableRateLimiting("secure-playback")]
    [RequestSizeLimit(8 * 1024)]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> Close(
        Guid sessionId,
        [FromBody] SecurePlaybackCloseRequest? request,
        CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store, private";
        Response.Headers.Pragma = "no-cache";

        var validation = await ValidateSessionAsync(
            sessionId,
            Request.Headers["X-Playback-Session-Token"].ToStringOrFallback(request?.HeartbeatToken),
            requireSource: false,
            ct);
        if (validation.Error is not null) return validation.Error;

        var session = validation.Session!;
        if (!session.Revoked)
        {
            session.Revoked = true;
            session.RevokedAt = DateTimeOffset.UtcNow;
            session.RevocationReason = "ClientClosed";
            await _worker.StopAsync(session.Id, ct);
            await _db.SaveChangesAsync(ct);
        }

        return NoContent();
    }

    private async Task<ValidatedSecureSession> ValidateSessionAsync(
        Guid sessionId,
        string? playbackToken,
        bool requireSource,
        CancellationToken ct)
    {
        var session = await _db.PlaybackSessions.FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is null) return new(null, null, NotFound());

        if (!IsPublicPlaybackSession(session.UserId))
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId)) return new(null, null, Unauthorized());
            if (session.UserId != userId) return new(null, null, Forbid());
        }

        if (session.Revoked) return new(null, null, Conflict(new { error = "Session revoked." }));
        if (DateTimeOffset.UtcNow > session.ExpiresAt) return new(null, null, Conflict(new { error = "Session expired." }));

        if (!TokenMatches(playbackToken, session.HeartbeatTokenHash))
            return new(null, null, Forbid());

        var video = await _db.Videos.FirstOrDefaultAsync(v => v.Id == session.VideoId, ct);
        if (video is null) return new(null, null, NotFound());
        if (video.PlaybackProvider != PlaybackProvider.SecureWebRtc)
            return new(null, null, Conflict(new { error = "This session is not a Secure WebRTC session." }));

        if (!requireSource)
            return new(session, video, null);

        if (string.IsNullOrWhiteSpace(video.ProtectedSourcePath))
            return new(null, null, Conflict(new { error = "Protected source media is not available." }));

        bool sourceExists;
        try
        {
            sourceExists = await _storage.ExistsAsync(video.ProtectedSourcePath, ct);
        }
        catch (InvalidOperationException)
        {
            return new(null, null, Conflict(new { error = "Protected source media is invalid." }));
        }

        return sourceExists
            ? new(session, video, null)
            : new(null, null, Conflict(new { error = "Protected source media is not available." }));
    }

    private static bool TryBuildEndpoint(string template, PlaybackSession session, Video video, out Uri endpoint)
    {
        var url = template
            .Replace("{sessionId}", session.Id.ToString("N"), StringComparison.Ordinal)
            .Replace("{videoId}", video.Id.ToString("N"), StringComparison.Ordinal);

        if (Uri.TryCreate(url, UriKind.Absolute, out var parsed))
        {
            endpoint = parsed;
            return true;
        }

        endpoint = null!;
        return false;
    }

    private static bool IsTransientWorkerStartupStatus(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.NotFound
            or HttpStatusCode.Conflict
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;

    private static bool IsPublicPlaybackSession(string userId) =>
        userId.StartsWith("embed:", StringComparison.Ordinal) ||
        userId.StartsWith("demo:", StringComparison.Ordinal);

    private static bool TokenMatches(string? supplied, string? expectedHash)
    {
        if (string.IsNullOrWhiteSpace(supplied) || string.IsNullOrWhiteSpace(expectedHash))
            return false;

        var suppliedHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(supplied))).ToLowerInvariant();
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(suppliedHash),
            Encoding.UTF8.GetBytes(expectedHash));
    }

    private sealed record ValidatedSecureSession(PlaybackSession? Session, Video? Video, ActionResult? Error);
}

internal static class HeaderStringExtensions
{
    public static string? ToStringOrFallback(this Microsoft.Extensions.Primitives.StringValues header, string? fallback)
    {
        var value = header.ToString();
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }
}
