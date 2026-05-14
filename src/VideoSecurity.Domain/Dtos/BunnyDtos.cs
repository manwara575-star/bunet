namespace VideoSecurity.Domain.Dtos;

/// <summary>Result of POST /library/{libraryId}/videos.</summary>
public sealed record BunnyCreateVideoResult(string Guid, long LibraryId, string Title, int Status);

/// <summary>Status snapshot from Bunny GET /library/{libraryId}/videos/{videoId}.</summary>
public sealed record BunnyVideoInfo(
    string Guid,
    long LibraryId,
    string Title,
    int Status,
    double Length,
    DateTimeOffset DateUploaded,
    string? CollectionId);

/// <summary>Credentials for a TUS upload — server-issued, time-limited.</summary>
public sealed record BunnyTusUploadCredentials(
    string TusEndpoint,
    string AuthorizationSignature,
    long AuthorizationExpire,
    string VideoId,
    long LibraryId,
    string FileName);

/// <summary>Webhook payload received from Bunny when video processing changes.</summary>
public sealed record BunnyWebhookPayload(
    string VideoLibraryId,
    string VideoGuid,
    int Status);
