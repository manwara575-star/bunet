# Enterprise Video Security Plan for Bunny.net Stream + ASP.NET Core

## Summary

Build a greenfield ASP.NET Core video-security layer that uses Bunny.net Stream for upload, storage, transcoding, DRM-protected playback, and CDN delivery. The primary goal is to stop CocoCut-style HLS/M3U8/TS downloading. The secondary goal is to deter and trace recording mode with best-effort browser hardening and visible forensic watermarking.

The protected playback path will be **Bunny Embed only**, because Bunny MediaCage Basic DRM requires Embed View and disables direct third-party-player access. The system will not expose raw M3U8, TS, DASH, or MP4 URLs from the app.

## Key Changes

- Configure Bunny Stream library:
  - Enable **MediaCage Basic DRM**.
  - Enable **Embed View Token Authentication**.
  - Enable **Block Direct URL File Access**.
  - Restrict **Allowed Domains** to exact production/staging domains.
  - Disable **MP4 Fallback**, **Early-Play**, and **Keep Original Files**.
  - Use Bunny Stream storage only; do not keep public original files.
- Configure CDN protection:
  - Use **Advanced CDN Token Authentication** with HMAC-SHA256 only.
  - Use **path-based directory tokens** for any HLS/DASH path that must be signed, so playlist and segment requests inherit protection.
  - Use balanced token binding: short TTL, session binding, optional risk-based IP validation; avoid mandatory IP lock by default.
- Build ASP.NET Core backend services:
  - `BunnyStreamClient`: typed `HttpClient` or OpenAPI-generated client for Stream API.
  - `BunnyTusUploadSigner`: creates admin-only TUS upload credentials.
  - `BunnyEmbedTokenSigner`: signs Bunny iframe URLs server-side.
  - `BunnyCdnTokenSigner`: signs direct CDN paths only when unavoidable.
  - `VideoEntitlementService`: checks user/course/subscription access before playback.
  - `PlaybackSessionService`: creates session IDs, TTLs, heartbeat state, and abuse telemetry.
- Public backend API contract:
  - `POST /api/admin/videos`: admin creates Bunny video object and receives TUS upload credentials.
  - `GET /api/admin/videos/{id}`: admin reads local/Bunny processing status.
  - `POST /api/videos/{id}/playback-session`: authorized learner receives signed embed URL, session ID, expiry, and signed watermark payload.
  - `POST /api/videos/heartbeat`: records active playback, focus/visibility state, and progress.
  - `POST /api/security/video-events`: records suspected recording/download indicators.
  - `POST /api/webhooks/bunny/stream`: receives Bunny video processing updates.
- Data model:
  - `Video`: local ID, Bunny video GUID, library ID, title, status, protected flag, duration, collection/course mapping.
  - `VideoAccessGrant`: user/course/video entitlement.
  - `PlaybackSession`: user ID, video ID, session ID, expiry, IP hash, user-agent hash, risk score, revoked flag.
  - `VideoProgress`: progress and completion state.
  - `VideoSecurityEvent`: event type, session ID, user ID, video ID, metadata, timestamp.
- Frontend protected player:
  - Render only a signed Bunny iframe URL from `/playback-session`.
  - Do not render raw HLS/MP4 URLs in DOM, JSON, logs, or analytics.
  - Disable Bunny iframe native fullscreen; provide app-level fullscreen wrapper so the overlay watermark remains visible.
  - Add moving watermark overlay containing **User ID + timestamp + session marker**, with randomized positions and opacity.
  - Add best-effort hardening: `Permissions-Policy: display-capture=(), picture-in-picture=()`, strict CSP, `Referrer-Policy: strict-origin-when-cross-origin`, no download links, no right-click download UI.
- Recording-mode strategy:
  - Treat browser/OS recording as impossible to fully block with free web-only controls.
  - Use visible moving watermarking as the primary free deterrent and leak-tracing layer.
  - Use best-effort detection only for telemetry, not as a security guarantee.
  - Add optional future upgrade path to Bunny MediaCage Enterprise DRM for Widevine/FairPlay output protection.

## Open-Source / Free Supporting Tools

- `tus-js-client`: browser admin upload to Bunny Stream using server-issued credentials.
- `FFmpeg`: optional pre-upload static watermarking for especially sensitive videos before Bunny upload.
- `OpenTelemetry + Prometheus/Grafana/Loki`: logs, metrics, and playback/security monitoring.
- `OWASP ZAP`: API and header security scans.
- `Playwright`: E2E validation that raw video URLs are not exposed and watermark/fullscreen behavior works.
- `WireMock.Net`: integration tests for Bunny API failure/success paths.
- Do **not** use `hls.js` or Shaka Player for protected v1 playback, because MediaCage Basic requires Bunny Embed. Shaka becomes relevant only if the project later upgrades to Enterprise DRM/custom player.

## AI Agent Work Split

- **ChatGPT 5.5**
  - Own threat model, architecture review, security acceptance criteria, API contract review, and final security audit.
  - Review token-signing code, session lifecycle, abuse telemetry, and test coverage.
  - Produce adversarial test cases for CocoCut-style download attempts and copied-token replay.
- **Cloud Opus 4.7**
  - Own implementation-heavy coding in ASP.NET Core, EF Core migrations, typed clients, controllers, services, frontend player wrapper, and tests.
  - Implement Bunny API/TUS integration, watermark overlay, headers, and CI checks.
  - Fix issues found by ChatGPT 5.5 review.
- **GitHub Copilot**
  - Use for boilerplate and local code completion only.
  - Never give Copilot or either AI model real Bunny API keys, token keys, production secrets, or customer data.

## Test Plan

- Unit tests:
  - Embed token SHA256 signing and expiry.
  - CDN HMAC-SHA256 path-token signing, including directory token behavior.
  - TUS upload signature generation.
  - Entitlement denial, expired sessions, revoked sessions, and no-secret response checks.
- Integration tests:
  - Mock Bunny Stream create-video/upload/status/webhook flows.
  - Verify admin-only upload endpoints.
  - Verify playback session cannot be created without entitlement.
- Browser/E2E tests:
  - Authorized user receives Bunny iframe only.
  - DOM/API responses contain no `.m3u8`, `.ts`, raw CDN video path, or `.mp4` playback URL.
  - Wrapper fullscreen keeps watermark visible.
  - `display-capture=()` blocks app-initiated `getDisplayMedia()`.
- Manual security validation:
  - CocoCut standard detection/download and Force Download must not produce usable unencrypted video.
  - Copied iframe URL fails after expiry.
  - Direct video/CDN URL access fails without valid token/referrer.
  - Recording mode shows moving User ID + time watermark in captured footage.

## Assumptions and Defaults

- Target stack is **ASP.NET Core**.
- Protected playback is **Bunny Embed only**.
- Device policy is **modern browsers only**.
- Token policy is **balanced**, not mandatory IP locking.
- Original source files are **not retained** after Bunny processing.
- Upload flow is **admin TUS upload** with server-generated credentials.
- Recording defense is **deterrence + best-effort hardening**, not a promise of full prevention.
- Real screen-recording prevention requires paid Enterprise DRM or OS/browser-level DRM output protection.

## Research Basis

- Bunny Stream security: https://docs.bunny.net/stream/security
- Bunny security options: https://docs.bunny.net/stream/security-options
- MediaCage Basic DRM: https://docs.bunny.net/stream/mediacage-basic-guide
- Embed token authentication: https://docs.bunny.net/stream/token-authentication
- Advanced CDN token auth: https://docs.bunny.net/cdn/security/token-authentication/advanced
- Bunny encoding/security options: https://docs.bunny.net/stream/encoding
- Bunny TUS uploads: https://docs.bunny.net/stream/tus-resumable-uploads
- CocoCut HLS/recording behavior: https://cococut.net/tutorial.html
- Chrome tab capture capability: https://developer.chrome.com/docs/extensions/reference/api/tabCapture
- Browser display-capture policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy/display-capture
- W3C Clear Key limitation: https://www.w3.org/TR/encrypted-media-2/
