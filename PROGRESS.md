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
| Production VPS deployment to `cifm.polytronx.com` | done |
| Live public Secure WebRTC browser validation | done |

## Verification commands

```powershell
dotnet build VideoSecurity.slnx -c Release
dotnet test VideoSecurity.slnx -c Release --no-build
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check-no-raw-urls.ps1
```

## Operator follow-up for live CocoCut validation

The VPS deployment is live with the app and MediaMTX worker. A public Secure
WebRTC sample is available at:

```text
https://cifm.polytronx.com/demo/45b4bace-daf0-4aef-8262-e354fbe0ff7f
```

External headless Chromium validation passed: WHEP returned 200, audio/video
tracks became live, and checked same-origin HTML/JSON/JS responses contained no
`.m3u8`, `.mpd`, `.m4s`, `.ts`, `.mp4`, or `b-cdn` leaks.

Final named CocoCut validation still requires a machine with the actual CocoCut
extension/app. For the user's real Bunny-uploaded video, upload the original
source file through Secure WebRTC mode first; the Bunny-only iframe mode remains
the standard/scalable path and is not the high-security anti-download mode.
