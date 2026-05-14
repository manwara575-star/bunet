# PRD — Enterprise Hardening (ChatGPT Improvements Pass)

## Goal
Apply the 22-section ChatGPT improvement plan on top of the existing
Bunny Embed-only + MediaCage Basic + signed-embed architecture without
breaking the 42 existing unit/integration tests or the Playwright E2E
smoke suite.

## Current state (as of this PRD)
- Domain: `Video`, `VideoAccessGrant`, `PlaybackSession`, `VideoProgress`,
  `VideoSecurityEvent`, `BunnyWebhookReceipt`.
- Services: `PlaybackSessionService`, `VideoEntitlementService`,
  `SecurityEventService`, `BunnyEmbedTokenSigner`, `BunnyCdnTokenSigner`,
  `BunnyTusUploadSigner`, `BunnyStreamClient`.
- Web: SecurityHeadersMiddleware, rate-limit policies (anon-events,
  heartbeat, session-create), Bunny webhook with body-hash idempotency
  + HMAC verification, OpenTelemetry tracing/metrics scaffold.
- Identity: ASP.NET Identity, `Admin` role only. Strict cookies, antiforgery.
- Tests: 42 dotnet tests + Playwright smoke (3 cases).

## Decisions (from clarification popup, 2026-05-14)
- Scope: **all 22 sections**.
- DB: add EF migration; auto-apply on startup in Dev only.
- RBAC: keep existing `Admin` as alias for new `SuperAdmin`. Add
  `VideoAdmin`, `SecurityAuditor`, `SupportAgent`. Seed all roles.
- Telemetry: Prometheus scrape endpoint at `/metrics`. No external collector.
- Tracking: Ralph-style PRD.md + PROGRESS.md.

## Workstreams (parallel subagents)
1. **Domain + Migration** — Sensitivity tier, VideoSecurityPolicy,
   AuditLog, SigningKeyVersion, webhook idempotency by event id,
   PlaybackSession new fields (DeviceFingerprintHash, WatermarkPayloadHash,
   PlaybackStartedAtUtc, LastKnownPositionSeconds).
2. **Risk scoring + auto-revocation** — Policy thresholds 0–30 / 31–60 /
   61–80 / 81–100, raise score from heartbeat + security events,
   revoke at 81+, concurrent session enforcement.
3. **RBAC + admin endpoints + rate limiting** — 4 roles seeded,
   `/api/admin/videos/{id}/revoke-sessions`, `/api/admin/users/{id}/revoke-video-access`,
   tighten rate limits, AuditLog writes for sensitive actions.
4. **OpenTelemetry /metrics** — Prometheus exporter, custom meter
   `VideoSecurity.Security` with playback / security / bunny counters.
5. **Watermark hardening** — MutationObserver tamper detect, layered
   diagonal pattern, privacy-safe masked defaults, watermarkVisible
   in heartbeat payload.
6. **Webhook hardening + dynamic TUS expiry** — idempotency by event id,
   async retry queue, TUS expiry = max(1h, estimated upload time).
7. **CI leak gate + Playwright assertions** — workflow step greps
   responses for `.m3u8|.ts|.mp4`, Playwright authenticated case asserts
   no raw URL in DOM/network/state.
8. **Momus review** — runs `dotnet test` + `npx playwright test`,
   fixes regressions, updates PROGRESS.md.

## Non-goals
- Replacing MediaCage Basic with Enterprise DRM.
- Replacing SQLite with Postgres.
- Adding Redis (rate limiter stays in-memory for v1).
- Building a Shaka/hls.js custom player.

## Acceptance
- `dotnet test VideoSecurity.slnx` passes (≥ 42 + new tests).
- `npx playwright test` passes (smoke + new authenticated cases).
- New `security-leak-gate` CI step succeeds.
- `/metrics` returns Prometheus text exposition format.
- Admin can revoke all sessions for a video and all access for a user.
- High-risk session is auto-revoked after threshold breach.
- Removing the watermark DOM increments risk score and emits event.
