using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using VideoSecurity.Domain.Abstractions;
using VideoSecurity.Domain.Dtos;
using VideoSecurity.Infrastructure.Configuration;

namespace VideoSecurity.Infrastructure.Bunny;

public sealed class BunnyStreamClient : IBunnyStreamClient
{
    private readonly HttpClient _http;
    private readonly IBunnyOptionsProvider _options;
    private readonly ILogger<BunnyStreamClient> _log;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public BunnyStreamClient(HttpClient http, IBunnyOptionsProvider options, ILogger<BunnyStreamClient> log)
    {
        _http = http;
        _options = options;
        _log = log;
        _http.DefaultRequestHeaders.Accept.Clear();
        _http.DefaultRequestHeaders.Accept.Add(new("application/json"));
    }

    public async Task<BunnyCreateVideoResult> CreateVideoAsync(string title, string? collectionId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(title)) throw new ArgumentException("title required", nameof(title));
        var opts = await _options.GetAsync(ct);

        var body = new Dictionary<string, object?> { ["title"] = title };
        if (!string.IsNullOrEmpty(collectionId)) body["collectionId"] = collectionId;

        using var req = new HttpRequestMessage(HttpMethod.Post, BuildUri(opts, $"library/{opts.LibraryId}/videos"))
        {
            Content = JsonContent.Create(body, options: Json)
        };
        req.Headers.Add("AccessKey", opts.ApiKey);
        using var resp = await _http.SendAsync(req, ct);
        await EnsureSuccess(resp, ct);

        var json = await resp.Content.ReadFromJsonAsync<JsonElement>(Json, ct);
        return new BunnyCreateVideoResult(
            Guid: json.GetProperty("guid").GetString() ?? throw new InvalidOperationException("guid missing"),
            LibraryId: json.TryGetProperty("videoLibraryId", out var lib) && lib.ValueKind == JsonValueKind.Number ? lib.GetInt64() : opts.LibraryId,
            Title: json.TryGetProperty("title", out var t) ? t.GetString() ?? title : title,
            Status: json.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : 0);
    }

    public async Task<BunnyVideoInfo> GetVideoAsync(string videoId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(videoId);
        var opts = await _options.GetAsync(ct);
        using var req = new HttpRequestMessage(HttpMethod.Get, BuildUri(opts, $"library/{opts.LibraryId}/videos/{videoId}"));
        req.Headers.Add("AccessKey", opts.ApiKey);
        using var resp = await _http.SendAsync(req, ct);
        await EnsureSuccess(resp, ct);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>(Json, ct);
        return new BunnyVideoInfo(
            Guid: json.GetProperty("guid").GetString()!,
            LibraryId: json.TryGetProperty("videoLibraryId", out var lib) ? lib.GetInt64() : opts.LibraryId,
            Title: json.TryGetProperty("title", out var t) ? t.GetString() ?? string.Empty : string.Empty,
            Status: json.TryGetProperty("status", out var s) ? s.GetInt32() : 0,
            Length: json.TryGetProperty("length", out var l) && l.ValueKind == JsonValueKind.Number ? l.GetDouble() : 0,
            DateUploaded: json.TryGetProperty("dateUploaded", out var d) && d.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(d.GetString(), out var dt) ? dt : DateTimeOffset.UtcNow,
            CollectionId: json.TryGetProperty("collectionId", out var c) ? c.GetString() : null);
    }

    public async Task<IReadOnlyList<BunnyVideoInfo>> ListVideosAsync(CancellationToken ct, int page = 1, int perPage = 100)
    {
        var opts = await _options.GetAsync(ct);
        using var req = new HttpRequestMessage(HttpMethod.Get,
            BuildUri(opts, $"library/{opts.LibraryId}/videos?page={page}&itemsPerPage={perPage}&orderBy=date"));
        req.Headers.Add("AccessKey", opts.ApiKey);
        using var resp = await _http.SendAsync(req, ct);
        await EnsureSuccess(resp, ct);
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>(Json, ct);

        var items = new List<BunnyVideoInfo>();
        if (json.TryGetProperty("items", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var v in arr.EnumerateArray())
            {
                items.Add(new BunnyVideoInfo(
                    Guid: v.GetProperty("guid").GetString()!,
                    LibraryId: v.TryGetProperty("videoLibraryId", out var lib) ? lib.GetInt64() : opts.LibraryId,
                    Title: v.TryGetProperty("title", out var t) ? t.GetString() ?? string.Empty : string.Empty,
                    Status: v.TryGetProperty("status", out var s) ? s.GetInt32() : 0,
                    Length: v.TryGetProperty("length", out var l) && l.ValueKind == JsonValueKind.Number ? l.GetDouble() : 0,
                    DateUploaded: v.TryGetProperty("dateUploaded", out var d) && d.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(d.GetString(), out var dt) ? dt : DateTimeOffset.UtcNow,
                    CollectionId: v.TryGetProperty("collectionId", out var c) ? c.GetString() : null));
            }
        }
        return items;
    }

    public async Task DeleteVideoAsync(string videoId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(videoId);
        var opts = await _options.GetAsync(ct);
        using var req = new HttpRequestMessage(HttpMethod.Delete, BuildUri(opts, $"library/{opts.LibraryId}/videos/{videoId}"));
        req.Headers.Add("AccessKey", opts.ApiKey);
        using var resp = await _http.SendAsync(req, ct);
        await EnsureSuccess(resp, ct);
    }

    private async Task EnsureSuccess(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;
        var body = await resp.Content.ReadAsStringAsync(ct);
        _log.LogWarning("Bunny API call failed: {Status} {Reason} body={Body}", (int)resp.StatusCode, resp.ReasonPhrase, Truncate(body, 512));
        throw new HttpRequestException($"Bunny API {(int)resp.StatusCode}: {resp.ReasonPhrase}");
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";

    private static Uri BuildUri(BunnyOptions options, string path) =>
        new(new Uri(options.ApiBaseUrl.TrimEnd('/') + "/"), path);
}
