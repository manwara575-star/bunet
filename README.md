# VideoSecurity — Bunny Stream + ASP.NET Core

Greenfield enterprise video security layer that uses **Bunny.net Stream** for normal
upload/storage/transcoding plus an optional self-hosted **Secure WebRTC** mode for
high-security videos. Built on **ASP.NET Core (.NET 10)** with EF Core (SQLite),
ASP.NET Identity, and a Bunny **Embed-only** protected player.

> **Threat focus**
> 1. **Stop CocoCut-style HLS / M3U8 / TS / MP4 downloading** — primary, hard goal.
> 2. **Deter & trace screen recording** — best-effort browser hardening + visible
>    moving forensic watermark (User ID + session marker + timestamp).
>
> Real screen-recording prevention requires OS/vendor DRM. The free Secure WebRTC
> path targets downloader-mode tools by removing HLS/DASH/MP4 URLs from the browser;
> recordings are deterred/traced with watermarking.

## Architecture

```
src/
  VideoSecurity.Domain/          # Entities, DTOs, Abstractions (no deps)
  VideoSecurity.Infrastructure/  # EF Core, Identity stores, Bunny clients & signers, services
  VideoSecurity.Web/             # MVC + Razor Pages + API + Identity UI + Player + Admin
tests/
  VideoSecurity.UnitTests/       # Signers, entitlement, session lifecycle
  VideoSecurity.IntegrationTests # WireMock.Net Bunny mock + WebApplicationFactory
  e2e/                           # Playwright smoke (no raw URL leakage, security headers)
tools/
  watermark.ps1                  # Optional pre-upload FFmpeg watermark
```

## Key security properties

| Concern | Where | Notes |
|---|---|---|
| No raw `.m3u8` / `.ts` / `.mp4` ever in app DOM/logs | `PlayerController` only renders an iframe shell; a short-lived Bunny Embed URL is fetched via `/api/videos/{id}/playback-session` and assigned to `iframe.src` from JS. | Verified by leak tests and authenticated playback tests. |
| Signed Bunny **Embed Token** (SHA256) | `BunnyEmbedTokenSigner` | Per <https://docs.bunny.net/stream/token-authentication>. Library must have **MediaCage Basic DRM** + **Embed View Token Authentication** + **Block Direct URL File Access** + tight **Allowed Domains** + MP4 Fallback **off**. |
| Signed Bunny **TUS upload** credentials | `BunnyTusUploadSigner` | `SHA256(libraryId + apiKey + expire + videoId)` per <https://docs.bunny.net/stream/tus-resumable-uploads>. Library API key never reaches the browser. |
| Secure WebRTC mode for sensitive videos | `PlaybackProvider.SecureWebRtc`, `/api/secure-playback/{sessionId}/offer` | Stores the original file under protected server storage and proxies WebRTC offers to a configured WHEP-compatible worker. The browser receives signaling only; no `.m3u8`, `.ts`, `.m4s`, or `.mp4` URL is returned by the app. |
| Optional **CDN Advanced Token** signer (HMAC-SHA256, `HS256-`, `token_path`) | `BunnyCdnTokenSigner` | Only used if a non-Embed CDN URL must ever be exposed; v1 player path never calls it. |
| Server-side entitlement | `VideoEntitlementService` | Per-user, per-video and per-course grants with expiry + revocation. |
| Short-lived playback session | `PlaybackSessionService` | Default TTL is 15 minutes, IP/UA are HMAC-hashed (never raw), heartbeat updates progress + risk score, revocation supported. Already-issued Bunny embed URLs remain bearer tokens until expiry. |
| Hardening headers | `SecurityHeadersMiddleware` | CSP allows scripts from self only, `frame-src` whitelists `iframe.mediadelivery.net`, media is limited to self/blob for Secure WebRTC, `Permissions-Policy: display-capture=()`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`. |
| Forensic watermark | `wwwroot/js/player.js` + `wwwroot/css/player.css` | Two semi-transparent spans drift across the player every ~3.5s with `User · Session · UTC time`. App-level fullscreen keeps watermark above the iframe. |
| Webhook auth | `BunnyWebhookController` | Fails closed. Accepts Bunny Stream HMAC headers or a configured `X-Bunny-Webhook-Secret`; validates library id, blocks status downgrades, and stores recent body hashes to ignore duplicate replays. |
| Telemetry | `SecurityEventService` + `/api/security/video-events` | Records visibility loss, focus loss, dev-tools heuristic, suspected recording. Anonymous events are rate-limited and cannot attach arbitrary session/video ids. |
| Identity | ASP.NET Core Identity + cookies, `Admin` role-policy, seeded admin via `Seed:*`. | Strict cookies (`SameSite=Strict`, `HttpOnly`, `Secure=Always`) plus global antiforgery for cookie-authenticated APIs. |

## Configuration

Bunny **never** stores its real secrets in source control. Use **dotnet user-secrets**
in dev and environment variables in prod (`docker-compose.yml` shows the variable names).

```powershell
cd src/VideoSecurity.Web
dotnet user-secrets init
dotnet user-secrets set "Bunny:LibraryId"      "12345"
dotnet user-secrets set "Bunny:ApiKey"         "<library-api-key>"
dotnet user-secrets set "Bunny:EmbedTokenKey"  "<library-embed-token-key>"
dotnet user-secrets set "Bunny:CdnHostname"    "vz-xxxxxx.b-cdn.net"
dotnet user-secrets set "Bunny:CdnTokenKey"    "<advanced-cdn-token-key>"   # optional
dotnet user-secrets set "Bunny:PrivacyHashPepper" "<long-random>"           # recommended
dotnet user-secrets set "Bunny:WebhookSecret"  "<long-random>"              # custom fallback; Bunny signed headers also supported
dotnet user-secrets set "Seed:AdminEmail"      "you@example.com"
dotnet user-secrets set "Seed:AdminPassword"   "<strong-password>"
dotnet user-secrets set "ProtectedMedia:RootPath" "C:\secure-video-sources"
dotnet user-secrets set "SecurePlayback:Enabled" "true"
dotnet user-secrets set "SecurePlayback:WhepEndpointTemplate" "http://localhost:8889/{sessionId}/whep"
dotnet user-secrets set "SecurePlayback:StartFfmpegOnSessionCreate" "true"
dotnet user-secrets set "SecurePlayback:RtspPublishUrlTemplate" "rtsp://localhost:8554/{sessionId}"
dotnet user-secrets set "SecurePlayback:BurnWatermark" "true"
```

Startup fails fast when required Bunny settings are missing or still set to placeholders.
Secure WebRTC session creation also fails closed unless `SecurePlayback:Enabled`,
`SecurePlayback:WhepEndpointTemplate`, burned watermarking, and the protected
source file are all valid.

The Bunny library itself must be configured (manually in the Bunny dashboard) with:

- **MediaCage Basic DRM** = ON
- **Embed View Token Authentication** = ON
- **Block Direct URL File Access** = ON
- **Allowed Domains** = exact production + staging hostnames only
- **MP4 Fallback** = OFF, **Early-Play** = OFF, **Keep Original Files** = OFF
- (Optional) **Advanced CDN Token Authentication** = ON, HMAC-SHA256

## Run

```powershell
dotnet restore VideoSecurity.slnx
dotnet build VideoSecurity.slnx
dotnet test VideoSecurity.slnx
dotnet run --project src/VideoSecurity.Web --urls https://localhost:5001
```

Visit:
- `/`                       — landing
- `/catalog`                — entitled user video catalog
- `/Identity/Account/Login` — sign in (admin seeded if `Seed:*` set)
- `/admin`                  — admin video list + grant access
- `/admin/upload`           — TUS upload to Bunny
- `/admin/upload`           — also supports Secure WebRTC source upload to protected storage
- `/player/watch/{guid}`    — protected player (auth + entitlement required)
- `/swagger`                — API explorer (Development only)

## API contract

| Method | Route | Auth | Purpose |
|---|---|---|---|
| POST | `/api/admin/videos` | Admin | Create Bunny video object + return TUS upload credentials |
| POST | `/api/admin/videos/secure` | Admin | Create Secure WebRTC video + upload original source into protected storage |
| POST | `/api/admin/videos/{id}/protected-source` | Admin | Attach/replace protected source for Secure WebRTC playback |
| GET  | `/api/admin/videos/{id}` | Admin | Read local + (best-effort) Bunny status |
| GET  | `/api/admin/videos` | Admin | List videos |
| DELETE | `/api/admin/videos/{id}` | Admin | Soft-delete locally + delete in Bunny |
| GET | `/api/admin/sessions` | Admin | List playback sessions |
| POST | `/api/admin/sessions/{sessionId}/revoke` | Admin | Revoke a playback session |
| GET | `/api/me/videos` | User | List videos the signed-in user may watch |
| GET | `/api/me/progress/{videoId}` | User | Read current progress for a video |
| POST | `/api/videos/{id}/playback-session` | User | Returns `{sessionId, embedUrl, expiresAt, watermark}` |
| POST | `/api/secure-playback/{sessionId}/offer` | User | Validates session and proxies a WebRTC/WHEP SDP offer to the configured worker |
| POST | `/api/secure-playback/{sessionId}/seek` | User | Token-bound Secure WebRTC seek; repositions the private FFmpeg worker without exposing media URLs |
| POST | `/api/secure-playback/{sessionId}/close` | User | Token-bound Secure WebRTC cleanup; revokes the session and stops its worker |
| POST | `/api/videos/heartbeat` | User | Updates session + progress + risk score |
| POST | `/api/security/video-events` | Anon | Records best-effort security telemetry |
| POST | `/api/webhooks/bunny/stream` | Bunny signature/secret | Updates local video status |
| GET | `/health/live` | Anon | Liveness probe |
| GET | `/health/ready` | Anon | Readiness probe with SQLite check |

## What this project does **not** promise

- It does **not** prevent screen recording from a determined user on a normal browser.
  No web-only solution can. Visible watermark + Bunny Embed DRM is the deterrent.
- Secure WebRTC mode does **not** make video unrecordable. It is designed to make
  CocoCut-style normal download mode fail by avoiding HLS/DASH/MP4 delivery.

## Pre-upload watermark helper

```powershell
.\tools\watermark.ps1 -Input source.mp4 -Output source.wm.mp4 -Text "INTERNAL ONLY"
```

## Docker

```powershell
docker compose up -d --build
```

Pass real Bunny secrets via an `.env` file (matching the variable names in `docker-compose.yml`).
**Never** commit that file.

Compose also starts a free self-hosted MediaMTX worker for Secure WebRTC mode.
By default the web container publishes protected sources with FFmpeg to
`rtsp://mediamtx:8554/{sessionId}` and proxies WHEP offers to
`http://mediamtx:8889/{sessionId}/whep`. Only MediaMTX UDP `8189` is published
for browser WebRTC media. For anything beyond local Docker, set
`MEDIAMTX_WEBRTC_ADDITIONAL_HOSTS` to the public hostname/IP that browsers can
reach.

`docker-compose.yml` disables HTTPS redirection only so the sample container is reachable on local HTTP port 8080. Put TLS in front for production and send `X-Forwarded-Proto=https` from the reverse proxy.

## Tests

| Suite | Command |
|---|---|
| Unit + Integration | `dotnet test VideoSecurity.slnx` |
| Playwright E2E | `cd tests/e2e; npm ci; npx playwright install --with-deps chromium; npx playwright test` |

CI: `.github/workflows/ci.yml` runs both on push/PR.

## Production deployment

> Treat this section as the canonical operator runbook. Anything not listed here
> defaults to the appsettings shipped in the image.

### Required environment variables

All Bunny secrets are bound from configuration; map them via the `.env` file
consumed by `docker-compose.yml` (or the equivalent secret store on your platform):

| Variable | Required | Purpose |
|---|---|---|
| `ASPNETCORE_ENVIRONMENT` | yes | Must be `Production` to load `appsettings.Production.json`. |
| `ConnectionStrings__DefaultConnection` | yes | EF Core SQLite connection string. Default: `Data Source=/data/videosecurity.db`. |
| `Bunny__LibraryId` | yes | Numeric Bunny Stream library ID. |
| `Bunny__ApiKey` | yes | Bunny library API key (≥ 16 chars). |
| `Bunny__EmbedTokenKey` | yes | Embed View Token Authentication Key (≥ 16 chars). |
| `Bunny__CdnHostname` | yes | Pull Zone hostname, must match `^[a-z0-9-]+\.b-cdn\.net$`. |
| `Bunny__CdnTokenKey` | optional | Only needed for Advanced URL token signing. |
| `Bunny__PrivacyHashPepper` | strongly recommended | 32+ char random secret for IP/UA audit hashing. Startup logs a warning if missing. |
| `Bunny__WebhookSecret` | recommended | Custom shared secret for the Bunny webhook fallback verifier. |
| `ProtectedMedia__RootPath` | yes for Secure WebRTC | Private source-file root outside `wwwroot`; Compose sets `/data/protected-media`. |
| `ProtectedMedia__MaxSourceBytes` | yes for Secure WebRTC | Maximum protected source upload size; Compose default is 10 GB. |
| `SecurePlayback__Enabled` | yes for Secure WebRTC | Must be `true` before Secure WebRTC sessions can be created. |
| `SecurePlayback__WhepEndpointTemplate` | yes for Secure WebRTC | WHEP worker URL, e.g. `http://mediamtx:8889/{sessionId}/whep` in Compose. |
| `SecurePlayback__StartFfmpegOnSessionCreate` | recommended | Compose default is `true`; starts one FFmpeg publisher per secure session. |
| `SecurePlayback__RtspPublishUrlTemplate` | yes when FFmpeg start is enabled | RTSP publish URL, e.g. `rtsp://mediamtx:8554/{sessionId}`. |
| `SecurePlayback__BurnWatermark` | yes for Secure WebRTC | Must stay `true`; the app rejects Secure WebRTC sessions if burned watermarking is disabled. |
| `SecurePlayback__VideoPreset` | optional | FFmpeg x264 preset for secure workers; Compose defaults to `superfast` for lower latency. |
| `SecurePlayback__VideoMaxRate` / `SecurePlayback__VideoBufferSize` | optional | Secure worker bitrate cap and VBV buffer; Compose defaults to `2200k` / `4400k`. |
| `SecurePlayback__OutputFrameRate` | optional | Secure worker output frame rate; Compose defaults to `25`. |
| `SecurePlayback__AudioBitrate` | optional | Secure worker Opus audio bitrate; Compose defaults to `96k`. |
| `SecurePlayback__StaleSessionTimeout` | optional | Time without heartbeat before secure workers are revoked; Compose defaults to `00:00:45`. |
| `MEDIAMTX_WEBRTC_ADDITIONAL_HOSTS` | yes outside local Docker | Browser-reachable hostname/IP advertised in MediaMTX WebRTC ICE candidates. |
| `MEDIAMTX_WEBRTC_UDP_PORT` | yes for Secure WebRTC | Public UDP port for WebRTC media; default `8189/udp`. |
| `Hosting__DisableHttpsRedirection` | situational | `true` only when TLS terminates at a proxy that forwards `X-Forwarded-Proto=https`. |
| `Seed__AdminEmail` / `Seed__AdminPassword` | first boot only | Used by `IdentitySeeder` to create the first admin. Rotate immediately after first login. |

`BunnyOptionsValidator` runs at startup and fails fast if any of the placeholder
strings (`<library-api-key>`, `your-`, `replace-me`, `changeme`, `xxxx`,
`REPLACE_WITH_USER_SECRETS_OR_ENV`) leak into a real deployment.

### TLS termination at the proxy

The container listens on plain HTTP `:8080` only. Terminate TLS at your reverse
proxy (Nginx, Caddy, Traefik, ALB, Cloudflare, etc.) and forward:

- `X-Forwarded-Proto: https`
- `X-Forwarded-For: <client-ip>`
- `Host: <public-hostname>`

ASP.NET Core's forwarded-headers middleware rewrites the request scheme so that
secure cookies, redirects, and CSP report URIs work correctly. Keep
`Hosting__DisableHttpsRedirection=true` when the proxy already enforces HTTPS,
otherwise leave it `false` (the production default).

### Bunny library configuration checklist

Re-link to the dashboard checklist in [Configuration](#configuration):

- **MediaCage Basic DRM** = ON
- **Embed View Token Authentication** = ON
- **Block Direct URL File Access** = ON
- **Allowed Domains** = exact production + staging hostnames only
- **MP4 Fallback** = OFF, **Early-Play** = OFF, **Keep Original Files** = OFF

### Health probes

| Probe | Path | What it checks |
|---|---|---|
| Liveness | `GET /health/live` | Process is up. |
| Readiness | `GET /health/ready` | SQLite reachable + **no pending EF Core migrations** (via `AppMigrationHealthCheck`). |

`docker-compose.yml` polls `/health/ready` every 30 s with `curl`; the Dockerfile
installs `curl` and `ffmpeg` in the final image for health checks and Secure
WebRTC worker publishing.

### Metrics scraping

Prometheus-compatible metrics are served at:

```
GET /metrics
GET /metrics/app
```

`/metrics` exposes the OpenTelemetry Prometheus scrape surface. `/metrics/app`
exposes DB-backed application gauges used by the hardening tests. Scrape both
from inside the trust boundary only. Restrict access to both paths via the
reverse proxy or by binding the metrics port to a private network if you split
it out.

### Database storage and backups

- **SQLite (default):** the persistent volume `videosec-data` mounts at `/data`.
  Back up `videosecurity.db`, `videosecurity.db-wal`, and `videosecurity.db-shm`
  atomically (e.g. `sqlite3 .backup` or `litestream`). Snapshot the volume at
  least daily and before every deploy.
- **Other database engines:** not supported by configuration alone today. The
  infrastructure currently registers SQLite explicitly, so PostgreSQL or SQL
  Server require a code-level provider change plus matching migrations.

### Secret rotation runbook

Rotate the following secrets on a regular cadence and after any suspected
compromise. The flow is intentionally low-risk:

1. **`Bunny__EmbedTokenKey`** — generate a new key in the Bunny dashboard,
   update the env var, and roll the container. Visit `/admin/keys` to confirm
   the application reports the new key fingerprint. Outstanding embed URLs stay
   valid until their expiry (default 15 minutes).
2. **`Bunny__ApiKey`** — rotate in the Bunny dashboard, then update the env var
   and roll the container. Admin upload + status calls will start using the new
   key on next boot. Confirm via `/admin/keys`.
3. **`Bunny__WebhookSecret`** — generate a new long random string, update both
   the Bunny webhook configuration and the env var, then roll the container.
   The webhook controller fails closed: requests carrying the old secret are
   rejected immediately after rotation, so coordinate with Bunny's retry window.

### Incident response

When investigating suspicious playback, scraping, or upload activity:

1. Pull the playback session list from `/admin/sessions` and revoke active
   sessions for the affected user.
2. Cross-reference the actor + timeline in `/admin/audit` (audit log of admin
   actions, key rotations, grants, and security policy changes).
3. Review `/admin/security` for client-side telemetry (focus loss, dev-tools
   heuristics, suspected screen recording) flagged for the same user/video.
4. If a key was exposed, follow the *Secret rotation runbook* above and force a
   password reset for impacted users.

