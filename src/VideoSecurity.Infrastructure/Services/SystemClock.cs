using VideoSecurity.Domain.Abstractions;

namespace VideoSecurity.Infrastructure.Services;

public sealed class SystemClock : ISystemClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
