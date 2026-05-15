using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Entities;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.Infrastructure.Services;

public sealed class FfmpegSecureMediaWorker : ISecureMediaWorker, IDisposable
{
    private readonly IProtectedMediaStorage _storage;
    private readonly SecurePlaybackOptions _options;
    private readonly ILogger<FfmpegSecureMediaWorker> _log;
    private readonly ConcurrentDictionary<Guid, Process> _processes = new();

    public FfmpegSecureMediaWorker(
        IProtectedMediaStorage storage,
        IOptions<SecurePlaybackOptions> options,
        ILogger<FfmpegSecureMediaWorker> log)
    {
        _storage = storage;
        _options = options.Value;
        _log = log;
    }

    public Task StartAsync(PlaybackSession session, Video video, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!_options.Enabled ||
            !_options.StartFfmpegOnSessionCreate ||
            string.IsNullOrWhiteSpace(_options.RtspPublishUrlTemplate))
        {
            return Task.CompletedTask;
        }

        if (string.IsNullOrWhiteSpace(video.ProtectedSourcePath))
            throw new InvalidOperationException("Secure WebRTC source is not configured for this video.");

        if (_processes.TryGetValue(session.Id, out var existing) && !existing.HasExited)
            return Task.CompletedTask;

        var sourcePath = _storage.GetFullPath(video.ProtectedSourcePath);
        var publishUrl = BuildTemplate(_options.RtspPublishUrlTemplate, session, video);

        var startInfo = new ProcessStartInfo
        {
            FileName = _options.FfmpegPath,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-hide_banner");
        startInfo.ArgumentList.Add("-loglevel");
        startInfo.ArgumentList.Add("warning");
        startInfo.ArgumentList.Add("-nostdin");
        startInfo.ArgumentList.Add("-re");
        startInfo.ArgumentList.Add("-i");
        startInfo.ArgumentList.Add(sourcePath);
        if (_options.BurnWatermark)
        {
            startInfo.ArgumentList.Add("-vf");
            startInfo.ArgumentList.Add(BuildWatermarkFilter(session.WatermarkPayload, _options.WatermarkFontSize));
        }
        startInfo.ArgumentList.Add("-c:v");
        startInfo.ArgumentList.Add("libx264");
        startInfo.ArgumentList.Add("-preset");
        startInfo.ArgumentList.Add("veryfast");
        startInfo.ArgumentList.Add("-tune");
        startInfo.ArgumentList.Add("zerolatency");
        startInfo.ArgumentList.Add("-pix_fmt");
        startInfo.ArgumentList.Add("yuv420p");
        startInfo.ArgumentList.Add("-profile:v");
        startInfo.ArgumentList.Add("baseline");
        startInfo.ArgumentList.Add("-level");
        startInfo.ArgumentList.Add("3.1");
        startInfo.ArgumentList.Add("-g");
        startInfo.ArgumentList.Add("30");
        startInfo.ArgumentList.Add("-bf");
        startInfo.ArgumentList.Add("0");
        startInfo.ArgumentList.Add("-c:a");
        startInfo.ArgumentList.Add("libopus");
        startInfo.ArgumentList.Add("-ar");
        startInfo.ArgumentList.Add("48000");
        startInfo.ArgumentList.Add("-ac");
        startInfo.ArgumentList.Add("2");
        startInfo.ArgumentList.Add("-f");
        startInfo.ArgumentList.Add("rtsp");
        startInfo.ArgumentList.Add("-rtsp_transport");
        startInfo.ArgumentList.Add("tcp");
        startInfo.ArgumentList.Add(publishUrl);

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start FFmpeg secure media worker.");

        if (!_processes.TryAdd(session.Id, process))
        {
            process.Kill(entireProcessTree: true);
            process.Dispose();
            return Task.CompletedTask;
        }

        _ = DrainAsync(process, session.Id);
        _log.LogInformation("Started secure media worker for session {SessionId}", session.Id);
        return Task.CompletedTask;
    }

    public Task StopAsync(Guid sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!_processes.TryRemove(sessionId, out var process))
            return Task.CompletedTask;

        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        finally
        {
            process.Dispose();
        }

        _log.LogInformation("Stopped secure media worker for session {SessionId}", sessionId);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        foreach (var sessionId in _processes.Keys.ToArray())
        {
            if (_processes.TryRemove(sessionId, out var process))
            {
                try
                {
                    if (!process.HasExited)
                        process.Kill(entireProcessTree: true);
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
    }

    private async Task DrainAsync(Process process, Guid sessionId)
    {
        try
        {
            var stderr = await process.StandardError.ReadToEndAsync();
            var stdout = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            _processes.TryRemove(sessionId, out _);
            if (process.ExitCode != 0)
                _log.LogWarning("Secure media worker for session {SessionId} exited with {ExitCode}: {Output}", sessionId, process.ExitCode, stderr + stdout);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Secure media worker output drain failed for session {SessionId}", sessionId);
        }
        finally
        {
            process.Dispose();
        }
    }

    private static string BuildTemplate(string template, PlaybackSession session, Video video) =>
        template
            .Replace("{sessionId}", session.Id.ToString("N"), StringComparison.Ordinal)
            .Replace("{videoId}", video.Id.ToString("N"), StringComparison.Ordinal);

    private static string BuildWatermarkFilter(string text, int fontSize)
    {
        var escaped = EscapeDrawTextValue(string.IsNullOrWhiteSpace(text) ? "Protected Session" : text);
        var size = Math.Clamp(fontSize, 14, 96);
        return "drawtext=" +
               $"text='{escaped}':" +
               "fontcolor=white@0.35:" +
               $"fontsize={size}:" +
               "box=1:" +
               "boxcolor=black@0.20:" +
               "x=mod(t*80\\,w-text_w):" +
               "y=mod(t*45\\,h-text_h)";
    }

    private static string EscapeDrawTextValue(string value) =>
        value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace(":", "\\:", StringComparison.Ordinal)
            .Replace("'", "\\'", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace(",", "\\,", StringComparison.Ordinal)
            .Replace("[", "\\[", StringComparison.Ordinal)
            .Replace("]", "\\]", StringComparison.Ordinal);
}
