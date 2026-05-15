using Microsoft.Extensions.Options;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.Infrastructure.Services;

public sealed class FileSystemProtectedMediaStorage : IProtectedMediaStorage
{
    private readonly ProtectedMediaOptions _options;
    private readonly string _rootPath;
    private readonly HashSet<string> _allowedExtensions;

    public FileSystemProtectedMediaStorage(IOptions<ProtectedMediaOptions> options)
    {
        _options = options.Value;
        _rootPath = Path.GetFullPath(_options.RootPath);
        _allowedExtensions = new HashSet<string>(_options.AllowedExtensions, StringComparer.OrdinalIgnoreCase);
    }

    public async Task<ProtectedMediaSaveResult> SaveSourceAsync(
        Guid videoId,
        string originalFileName,
        string contentType,
        Stream source,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(source);

        var safeName = Path.GetFileName(originalFileName);
        if (string.IsNullOrWhiteSpace(safeName))
            throw new InvalidOperationException("Source file name is required.");

        var ext = Path.GetExtension(safeName);
        if (string.IsNullOrWhiteSpace(ext) || !_allowedExtensions.Contains(ext))
            throw new InvalidOperationException($"File type '{ext}' is not allowed.");

        if (source.CanSeek && source.Length > _options.MaxSourceBytes)
            throw new InvalidOperationException("Source file exceeds the configured maximum size.");

        var relativePath = Path.Combine(videoId.ToString("N"), "source", $"{Guid.NewGuid():N}{ext.ToLowerInvariant()}");
        var fullPath = GetFullPath(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);

        await using var target = new FileStream(
            fullPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 1024 * 1024,
            useAsync: true);

        await source.CopyToAsync(target, ct);

        return new ProtectedMediaSaveResult(relativePath, safeName, contentType, target.Length);
    }

    public Task<bool> ExistsAsync(string relativePath, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(File.Exists(GetFullPath(relativePath)));
    }

    public string GetFullPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            throw new InvalidOperationException("Protected media path is required.");

        var fullPath = Path.GetFullPath(Path.Combine(_rootPath, relativePath));
        var rootWithSeparator = _rootPath.EndsWith(Path.DirectorySeparatorChar)
            ? _rootPath
            : _rootPath + Path.DirectorySeparatorChar;

        if (!fullPath.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Protected media path escapes the configured root.");

        return fullPath;
    }
}
