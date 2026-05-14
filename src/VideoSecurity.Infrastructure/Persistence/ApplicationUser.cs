using Microsoft.AspNetCore.Identity;

namespace VideoSecurity.Infrastructure.Persistence;

public class ApplicationUser : IdentityUser
{
    public string DisplayName { get; set; } = string.Empty;
}
