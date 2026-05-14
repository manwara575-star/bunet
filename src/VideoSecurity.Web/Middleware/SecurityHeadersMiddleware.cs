namespace VideoSecurity.Web.Middleware;

/// <summary>
/// Applies hardening headers focused on protected video playback:
///   - Strict CSP (restricts script/iframe sources)
///   - Permissions-Policy: blocks app-initiated screen capture and PiP
///   - Referrer-Policy + X-Content-Type-Options + X-Frame-Options
///   - Cross-Origin-Opener / Embedder where safe
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _embedFrameAncestors;

    public SecurityHeadersMiddleware(RequestDelegate next, IConfiguration config)
    {
        _next = next;

        // Build frame-ancestors for embed paths from configuration.
        var allowed = config.GetValue<string>("Embed:AllowedDomains") ?? "";
        var ancestors = "'self'";
        foreach (var domain in allowed.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            ancestors += $" https://{domain} http://{domain}";
        }
        _embedFrameAncestors = ancestors;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var h = ctx.Response.Headers;
        var isEmbedPath = ctx.Request.Path.StartsWithSegments("/embed");

        // CSP: embed paths allow external framing; all others restrict to self.
        var frameAncestors = isEmbedPath ? _embedFrameAncestors : "'self'";

        h["Content-Security-Policy"] =
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' data:; " +
            "connect-src 'self' https://video.bunnycdn.com; " +
            "frame-src https://iframe.mediadelivery.net; " +
            "media-src 'none'; " +
            "object-src 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'; " +
            $"frame-ancestors {frameAncestors}; " +
            "upgrade-insecure-requests;";

        h["Permissions-Policy"] =
            "display-capture=(), picture-in-picture=(), autoplay=(self), " +
            "camera=(), microphone=(), geolocation=(), encrypted-media=(self \"https://iframe.mediadelivery.net\")";

        h["Referrer-Policy"] = "strict-origin-when-cross-origin";
        h["X-Content-Type-Options"] = "nosniff";

        // X-Frame-Options: only set SAMEORIGIN for non-embed paths.
        // Embed paths rely on CSP frame-ancestors (which takes precedence in modern browsers).
        if (!isEmbedPath)
            h["X-Frame-Options"] = "SAMEORIGIN";

        h["Cross-Origin-Opener-Policy"] = "same-origin";
        h["X-Permitted-Cross-Domain-Policies"] = "none";

        await _next(ctx);
    }
}
