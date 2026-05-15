# PROGRESS - Secure WebRTC Anti-CocoCut Mode

| Workstream | Status |
|---|---|
| Playback provider schema, EF model, and migration | done |
| Protected source storage outside `wwwroot` with traversal checks | done |
| Admin Secure WebRTC upload and protected-source replacement endpoints | done |
| Secure playback session response with no embed/media URL | done |
| Same-origin WHEP offer proxy with session/user/token/source validation | done |
| Browser `RTCPeerConnection` player branch using `<video srcObject>` | done |
| FFmpeg worker hook with server-side burned watermark | done |
| MediaMTX Docker Compose worker wiring | done |
| CSP/player UX updates for WebRTC signaling and playback errors | done |
| Unit/integration coverage for no URL leaks, offer rejection, path traversal, upload, and worker stop | done |
| README and `.env.example` operator configuration | done |

## Verification commands

```powershell
dotnet build VideoSecurity.slnx -c Release
dotnet test VideoSecurity.slnx -c Release --no-build
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check-no-raw-urls.ps1
```

## Operator follow-up for live CocoCut validation

Live validation requires the VPS deployment to run the app and MediaMTX worker,
upload the original video through Secure WebRTC mode, expose UDP `8189` to the
browser, and test from a real browser with CocoCut, ffmpeg, yt-dlp, copied
URLs, incognito, and post-expiry replay.
