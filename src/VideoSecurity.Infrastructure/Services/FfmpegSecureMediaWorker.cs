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

    public Task StartAsync(PlaybackSession session, Video video, CancellationToken ct) =>
        StartProcessAsync(session, video, TimeSpan.Zero, ct);

    public Task SeekAsync(PlaybackSession session, Video video, TimeSpan position, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        StopProcess(session.Id);
        return StartProcessAsync(session, video, position, ct);
    }

    private Task StartProcessAsync(PlaybackSession session, Video video, TimeSpan position, CancellationToken ct)
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
        if (position > TimeSpan.Zero)
        {
            startInfo.ArgumentList.Add("-ss");
            startInfo.ArgumentList.Add(FormatTimestamp(position));
        }
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
        startInfo.ArgumentList.Add(string.IsNullOrWhiteSpace(_options.VideoPreset) ? "superfast" : _options.VideoPreset);
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
        if (_options.OutputFrameRate > 0)
        {
            startInfo.ArgumentList.Add("-r");
            startInfo.ArgumentList.Add(_options.OutputFrameRate.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        if (!string.IsNullOrWhiteSpace(_options.VideoMaxRate))
        {
            startInfo.ArgumentList.Add("-maxrate");
            startInfo.ArgumentList.Add(_options.VideoMaxRate);
        }
        if (!string.IsNullOrWhiteSpace(_options.VideoBufferSize))
        {
            startInfo.ArgumentList.Add("-bufsize");
            startInfo.ArgumentList.Add(_options.VideoBufferSize);
        }
        startInfo.ArgumentList.Add("-c:a");
        startInfo.ArgumentList.Add("libopus");
        if (!string.IsNullOrWhiteSpace(_options.AudioBitrate))
        {
            startInfo.ArgumentList.Add("-b:a");
            startInfo.ArgumentList.Add(_options.AudioBitrate);
        }
        startInfo.ArgumentList.Add("-ar");
        startInfo.ArgumentList.Add("48000");
        startInfo.ArgumentList.Add("-ac");
        startInfo.ArgumentList.Add("2");
        startInfo.ArgumentList.Add("-muxdelay");
        startInfo.ArgumentList.Add("0");
        startInfo.ArgumentList.Add("-muxpreload");
        startInfo.ArgumentList.Add("0");
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
        _log.LogInformation("Started secure media worker for session {SessionId} at {PositionSeconds:F1}s", session.Id, position.TotalSeconds);
        return Task.CompletedTask;
    }

    public Task StopAsync(Guid sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        StopProcess(sessionId);

        _log.LogInformation("Stopped secure media worker for session {SessionId}", sessionId);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        foreach (var sessionId in _processes.Keys.ToArray())
        {
            StopProcess(sessionId);
        }
    }

    private void StopProcess(Guid sessionId)
    {
        if (!_processes.TryRemove(sessionId, out var process))
            return;

        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (InvalidOperationException)
        {
        }
        finally
        {
            process.Dispose();
        }
    }

    private async Task DrainAsync(Process process, Guid sessionId)
    {
        var shouldDispose = false;
        try
        {
            var stderr = await process.StandardError.ReadToEndAsync();
            var stdout = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            shouldDispose = TryRemoveProcess(sessionId, process);
            if (process.ExitCode != 0)
                _log.LogWarning("Secure media worker for session {SessionId} exited with {ExitCode}: {Output}", sessionId, process.ExitCode, stderr + stdout);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Secure media worker output drain failed for session {SessionId}", sessionId);
        }
        finally
        {
            if (shouldDispose)
                process.Dispose();
        }
    }

    private bool TryRemoveProcess(Guid sessionId, Process process) =>
        ((ICollection<KeyValuePair<Guid, Process>>)_processes).Remove(new KeyValuePair<Guid, Process>(sessionId, process));

    private static string BuildTemplate(string template, PlaybackSession session, Video video) =>
        template
            .Replace("{sessionId}", session.Id.ToString("N"), StringComparison.Ordinal)
            .Replace("{videoId}", video.Id.ToString("N"), StringComparison.Ordinal);

    private static string FormatTimestamp(TimeSpan position) =>
        position.ToString(@"hh\:mm\:ss\.fff", System.Globalization.CultureInfo.InvariantCulture);

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
