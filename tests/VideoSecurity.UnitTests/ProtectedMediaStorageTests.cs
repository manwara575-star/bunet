using FluentAssertions;
using Microsoft.Extensions.Options;
using VideoSecurity.Infrastructure.Configuration;
using VideoSecurity.Infrastructure.Services;

namespace VideoSecurity.UnitTests;

public sealed class ProtectedMediaStorageTests
{
    [Fact]
    public async Task SaveSourceAsync_StoresInsideProtectedRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "videosec-storage-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var storage = new FileSystemProtectedMediaStorage(Options.Create(new ProtectedMediaOptions
            {
                RootPath = root,
                MaxSourceBytes = 1024,
                AllowedExtensions = [".mp4"]
            }));

            await using var source = new MemoryStream([1, 2, 3, 4]);
            var saved = await storage.SaveSourceAsync(Guid.NewGuid(), "sample.mp4", "video/mp4", source, default);

            saved.RelativePath.Should().NotContain("sample.mp4");
            saved.OriginalFileName.Should().Be("sample.mp4");
            (await storage.ExistsAsync(saved.RelativePath, default)).Should().BeTrue();
            storage.GetFullPath(saved.RelativePath).Should().StartWith(Path.GetFullPath(root));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("..\\escape.mp4")]
    [InlineData("../escape.mp4")]
    [InlineData("safe\\..\\..\\escape.mp4")]
    public void GetFullPath_RejectsRelativeRootEscape(string path)
    {
        var root = Path.Combine(Path.GetTempPath(), "videosec-storage-tests", Guid.NewGuid().ToString("N"));
        var storage = new FileSystemProtectedMediaStorage(Options.Create(new ProtectedMediaOptions
        {
            RootPath = root,
            AllowedExtensions = [".mp4"]
        }));

        var act = () => storage.GetFullPath(path);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*escapes*");
    }

    [Fact]
    public void GetFullPath_RejectsAbsoluteRootEscape()
    {
        var root = Path.Combine(Path.GetTempPath(), "videosec-storage-tests", Guid.NewGuid().ToString("N"));
        var storage = new FileSystemProtectedMediaStorage(Options.Create(new ProtectedMediaOptions
        {
            RootPath = root,
            AllowedExtensions = [".mp4"]
        }));

        var absolute = Path.Combine(Path.GetPathRoot(root)!, "outside-secure-root.mp4");
        var act = () => storage.GetFullPath(absolute);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*escapes*");
    }

    [Fact]
    public void GetFullPath_RejectsSiblingPrefixEscape()
    {
        var root = Path.Combine(Path.GetTempPath(), "videosec-root");
        var storage = new FileSystemProtectedMediaStorage(Options.Create(new ProtectedMediaOptions
        {
            RootPath = root,
            AllowedExtensions = [".mp4"]
        }));

        var siblingPrefix = Path.Combine(Path.GetTempPath(), "videosec-root-evil", "source.mp4");
        var act = () => storage.GetFullPath(siblingPrefix);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*escapes*");
    }
}
