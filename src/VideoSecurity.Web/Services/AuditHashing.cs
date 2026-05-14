using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.Web.Services;

internal static class AuditHashing
{
    public static string HashIp(BunnyOptions opts, HttpContext http)
    {
        var ip = http.Connection.RemoteIpAddress?.ToString() ?? $"unknown:{http.TraceIdentifier}";
        return Hash(opts, ip);
    }

    public static string HashUa(BunnyOptions opts, HttpContext http)
    {
        var ua = http.Request.Headers.UserAgent.ToString();
        return Hash(opts, ua);
    }

    public static string Hash(BunnyOptions opts, string input)
    {
        if (string.IsNullOrEmpty(input)) input = "-";
        var secret = !string.IsNullOrWhiteSpace(opts.PrivacyHashPepper) ? opts.PrivacyHashPepper : opts.EmbedTokenKey;
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(string.IsNullOrEmpty(secret) ? "-" : secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }
}
