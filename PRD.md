# PRD - Secure WebRTC Anti-CocoCut Mode

## Goal

Add a free/self-hosted high-security playback path that makes CocoCut-style
normal download mode fail by removing HLS, DASH, MP4, TS, M4S, and Bunny CDN
media URLs from the browser playback flow.

This mode is not a replacement for enterprise DRM and does not claim to stop
camera capture, OS-level recording, or a fully compromised client device.

## Scope

1. Keep the existing Bunny Stream signed-iframe path for normal videos.
2. Add `SecureWebRtc` as a separate playback provider for sensitive videos.
3. Store the original secure source file in protected server storage outside
   `wwwroot`.
4. Create a same-origin WebRTC/WHEP signaling API that validates user,
   session, expiry, revocation, protected source, and heartbeat token before it
   contacts the worker.
5. Use a self-hosted MediaMTX worker with FFmpeg publishing RTSP per session.
6. Burn a forensic watermark server-side before publishing the WebRTC stream.
7. Keep existing heartbeat, risk scoring, concurrency revocation, security
   headers, and leak-gate behavior.

## Non-goals

- Do not claim 100% prevention of screen recording or camera capture.
- Do not expose raw Bunny CDN, HLS, DASH, MP4, TS, or M4S URLs in Secure WebRTC.
- Do not require paid DRM, paid streaming infrastructure, or a browser
  extension.

## Architecture

```text
Browser
  -> POST /api/videos/{videoId}/playback-session
  -> receives session id, heartbeat token, and same-origin WHEP offer endpoint
  -> creates RTCPeerConnection and posts SDP offer
  -> receives encrypted WebRTC/SRTP media on <video srcObject>

ASP.NET Core
  -> validates entitlement, source storage, SecurePlayback config, session TTL
  -> starts FFmpeg when configured
  -> proxies SDP to MediaMTX WHEP endpoint
  -> revokes/stops worker on expiry, risk auto-revoke, or admin revoke

FFmpeg + MediaMTX
  -> FFmpeg reads private source file
  -> burns moving forensic watermark into frames
  -> publishes H.264 baseline + Opus over RTSP
  -> MediaMTX serves WHEP/WebRTC to the browser
```

## Acceptance

- Secure WebRTC session creation fails closed when worker config, watermarking,
  or protected source storage is invalid.
- Secure WebRTC responses do not contain `.m3u8`, `.mpd`, `.ts`, `.m4s`,
  `.mp4`, or `b-cdn` strings.
- WHEP offers reject missing/wrong heartbeat tokens, wrong users, expired
  sessions, revoked sessions, and invalid protected source paths.
- A valid WHEP answer can be proxied without returning downloadable media URLs.
- Admin secure upload creates a `SecureWebRtc` video with a protected source
  outside `wwwroot`.
- Risk auto-revocation stops the secure worker.
- Docker Compose includes the free MediaMTX worker and publishes only the
  required WebRTC UDP port.
- Build, unit/integration tests, and raw URL leak gate pass.
