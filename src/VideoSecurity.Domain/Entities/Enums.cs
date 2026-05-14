namespace VideoSecurity.Domain.Entities;

public enum VideoStatus
{
    Created = 0,
    Uploading = 1,
    Processing = 2,
    Ready = 3,
    Failed = 4,
    Deleted = 5
}

public enum SecurityEventType
{
    HeartbeatMissed = 0,
    VisibilityHidden = 1,
    FocusLost = 2,
    SuspectedRecording = 3,
    DevToolsOpen = 4,
    ScreenCaptureAttempt = 5,
    DownloadAttempt = 6,
    TokenReplay = 7,
    OriginMismatch = 8,
    WatermarkTamper = 9,
    ConcurrentSessionLimit = 10,
    RawUrlProbe = 11,
    EntitlementDenied = 12,
    RiskAutoRevoke = 13,
    Other = 99
}

public enum VideoSensitivityTier { Standard = 0, Premium = 1, Critical = 2 }

public enum SigningKeyPurpose { EmbedToken = 0, CdnToken = 1, WebhookSecret = 2, WatermarkSignature = 3 }

public enum AuditAction { VideoCreated = 0, VideoDeleted = 1, AccessGranted = 2, AccessRevoked = 3, SessionRevoked = 4, KeyRotated = 5, PolicyChanged = 6, RoleChanged = 7, AdminLogin = 8, Other = 99 }
