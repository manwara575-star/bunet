/* Protected video player wrapper.
 *
 * Responsibilities:
 *  - Fetch a signed Bunny embed URL from the backend (never rendered server-side).
 *  - Set the iframe src dynamically (URL never appears in initial HTML or logs).
 *  - Render a moving translucent watermark on top of the iframe.
 *  - Send heartbeats with visibility/focus state.
 *  - Emit best-effort security events.
 *  - Provide app-level fullscreen so the watermark stays on top.
 *
 * Free-tier limits we intentionally accept:
 *  - We CANNOT fully block screen recording from a browser tab.
 *  - We CANNOT prevent a determined user from inspecting the iframe's src in DevTools.
 *  - Our defenses are: short-lived signed URLs, DRM at Bunny, and visible forensic watermarking.
 */
window.VideoSecurity = window.VideoSecurity || {};

(function (VS) {
    'use strict';

    function postEvent(endpoint, body, antiForgery) {
        const headers = { 'Content-Type': 'application/json' };
        if (antiForgery) headers['RequestVerificationToken'] = antiForgery;

        if (antiForgery) {
            return fetch(endpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
                keepalive: true,
                credentials: 'same-origin'
            }).catch(() => { });
        }

        try {
            const blob = new Blob([JSON.stringify(body)], { type: 'application/json' });
            navigator.sendBeacon(endpoint, blob);
        } catch {
            fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body), keepalive: true }).catch(() => { });
        }
    }

    // --- Privacy mask: defense-in-depth in case a raw email / long digit run slips through. ---
    function maskSensitive(text) {
        if (!text) return text;
        let out = String(text);
        // Mask local-part of any email-looking token.
        out = out.replace(/([^\s@]+)@([^\s@]+\.[^\s@]+)/g, (_, local, domain) => {
            if (local.length <= 2) return local[0] + '*@' + domain;
            return local[0] + '*'.repeat(Math.max(1, local.length - 2)) + local[local.length - 1] + '@' + domain;
        });
        // Mask any run of 11+ digits (phone / national id) — keep first 2 and last 2.
        out = out.replace(/\d{11,}/g, m => m.slice(0, 2) + '*'.repeat(m.length - 4) + m.slice(-2));
        return out;
    }

    // --- Per-type debouncer (max 1 event per windowMs of same type). ---
    function makeEventDebouncer(windowMs) {
        const last = new Map();
        return function (type) {
            const now = Date.now();
            const prev = last.get(type) || 0;
            if (now - prev < windowMs) return false;
            last.set(type, now);
            return true;
        };
    }

    // --- Tiled diagonal watermark grid layer (CSS class + SVG data URL background). ---
    function installGrid(shell, gridText) {
        const existing = shell.querySelector('.player-watermark-grid');
        if (existing) existing.remove();

        const grid = document.createElement('div');
        grid.className = 'player-watermark-grid';
        grid.setAttribute('aria-hidden', 'true');

        const safe = String(gridText)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');

        // SVG tile: rotated text repeated across the shell. Final opacity comes from .player-watermark-grid (~0.07).
        const svg =
            "<svg xmlns='http://www.w3.org/2000/svg' width='360' height='200'>" +
              "<g fill='rgb(255,255,255)' font-family='system-ui,sans-serif' font-size='14' font-weight='600' opacity='0.9'>" +
                "<text x='10' y='110' transform='rotate(-30 10 110)'>" + safe + "</text>" +
                "<text x='190' y='40' transform='rotate(-30 190 40)'>" + safe + "</text>" +
                "<text x='190' y='180' transform='rotate(-30 190 180)'>" + safe + "</text>" +
              "</g>" +
            "</svg>";
        const url = "url(\"data:image/svg+xml;utf8," + encodeURIComponent(svg) + "\")";
        grid.style.backgroundImage = url + ", repeating-linear-gradient(45deg, rgba(255,255,255,0.08) 0, rgba(255,255,255,0.08) 1px, transparent 1px, transparent 14px)";

        const wm = shell.querySelector('#player-watermark');
        if (wm) shell.insertBefore(grid, wm); else shell.appendChild(grid);
        return grid;
    }

    function makeWatermarkSpan(text) {
        const s = document.createElement('span');
        s.textContent = text;
        s.style.top = (Math.random() * 80 + 5) + '%';
        s.style.left = (Math.random() * 70 + 5) + '%';
        s.style.opacity = (0.20 + Math.random() * 0.20).toFixed(2);
        s.style.fontSize = (12 + Math.random() * 6).toFixed(0) + 'px';
        return s;
    }

    function startWatermark(container, payload) {
        // Render 2 spans that re-position randomly every few seconds.
        container.appendChild(makeWatermarkSpan(payload.displayText));
        container.appendChild(makeWatermarkSpan(payload.displayText));

        function reposition() {
            const live = container.querySelectorAll('span');
            for (const s of live) {
                s.style.top = (Math.random() * 80 + 5) + '%';
                s.style.left = (Math.random() * 70 + 5) + '%';
                s.style.opacity = (0.20 + Math.random() * 0.20).toFixed(2);
                s.style.fontSize = (12 + Math.random() * 6).toFixed(0) + 'px';
            }
        }
        reposition();
        return setInterval(reposition, 3500);
    }

    // --- Visibility helpers used by both heartbeat and tamper guard. ---
    function isSpanHidden(span) {
        if (!span || !span.isConnected) return true;
        const cs = getComputedStyle(span);
        if (cs.display === 'none') return true;
        if (cs.visibility === 'hidden' || cs.visibility === 'collapse') return true;
        if (parseFloat(cs.opacity || '1') < 0.05) return true;
        const r = span.getBoundingClientRect();
        if (r.width < 1 || r.height < 1) return true;
        return false;
    }

    function anySpanVisible(container) {
        if (!container || !container.isConnected) return false;
        const cs = getComputedStyle(container);
        if (cs.display === 'none' || cs.visibility === 'hidden') return false;
        if (parseFloat(cs.opacity || '1') < 0.05) return false;
        const live = container.querySelectorAll('span');
        for (const s of live) {
            if (!isSpanHidden(s)) return true;
        }
        return false;
    }

    /*
     * Defensive tamper guard.
     *  - MutationObserver on the watermark container (childList/attrs/subtree).
     *  - A second observer on the shell rebuilds the container if it's removed entirely.
     *  - Periodic sweep re-asserts state in case observers are detached.
     *  - On any tamper: reinsert missing/hidden spans and POST a debounced WatermarkTamper event.
     */
    function installTamperGuard(shell, displayText, gridText, opts, sessionId) {
        const wmId = 'player-watermark';
        const debounce = makeEventDebouncer(3000);

        function reportTamper(reason) {
            if (!debounce('WatermarkTamper')) return;
            postEvent(opts.eventsEndpoint, {
                sessionId: sessionId,
                videoId: opts.videoId,
                type: 'WatermarkTamper',
                metadata: reason
            }, opts.antiForgery);
        }

        function unhide(el) {
            const s = el.style;
            if (s.display === 'none') s.display = '';
            if (s.visibility === 'hidden' || s.visibility === 'collapse') s.visibility = '';
            if (s.opacity && parseFloat(s.opacity) < 0.05) s.opacity = '';
            if (s.pointerEvents === 'none') s.pointerEvents = '';
        }

        function rebuildSpans(container) {
            while (container.firstChild) container.removeChild(container.firstChild);
            container.appendChild(makeWatermarkSpan(displayText));
            container.appendChild(makeWatermarkSpan(displayText));
        }

        function ensureGrid() {
            if (!shell.querySelector('.player-watermark-grid')) {
                installGrid(shell, gridText);
            }
        }

        let containerObserver = null;

        function ensureContainer() {
            let wm = document.getElementById(wmId);
            if (!wm) {
                wm = document.createElement('div');
                wm.id = wmId;
                wm.className = 'player-watermark';
                wm.setAttribute('aria-hidden', 'true');
                shell.appendChild(wm);
                rebuildSpans(wm);
                attachContainerObserver(wm);
                reportTamper('container-recreated');
            }
            return wm;
        }

        function attachContainerObserver(wm) {
            if (containerObserver) containerObserver.disconnect();
            containerObserver = new MutationObserver(() => {
                let tampered = false;
                let reason = '';
                unhide(wm);
                if (!wm.classList.contains('player-watermark')) {
                    wm.classList.add('player-watermark');
                    tampered = true; reason = reason || 'class-stripped';
                }
                const live = wm.querySelectorAll('span');
                if (live.length < 2) {
                    rebuildSpans(wm);
                    tampered = true; reason = reason || 'span-removed';
                } else {
                    for (const s of live) {
                        if (isSpanHidden(s)) {
                            unhide(s);
                            tampered = true; reason = reason || 'span-hidden';
                        }
                    }
                }
                ensureGrid();
                if (tampered) reportTamper(reason);
                // Note: never log mutation records — they may carry watermark text.
            });
            containerObserver.observe(wm, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['style', 'class', 'hidden']
            });
        }

        // Shell-level observer: catches removal of the entire watermark container or grid.
        const shellObserver = new MutationObserver(() => {
            ensureContainer();
            ensureGrid();
        });
        shellObserver.observe(shell, { childList: true, subtree: false });

        const wm = ensureContainer();
        attachContainerObserver(wm);

        // Fallback periodic reassertion in case observers themselves are detached.
        const sweepTimer = setInterval(() => {
            const cur = ensureContainer();
            ensureGrid();
            if (!anySpanVisible(cur)) {
                rebuildSpans(cur);
                reportTamper('sweep-no-visible-span');
            }
        }, 5000);

        return {
            isVisible: () => anySpanVisible(document.getElementById(wmId)),
            stop: () => {
                clearInterval(sweepTimer);
                if (containerObserver) containerObserver.disconnect();
                shellObserver.disconnect();
            }
        };
    }

    VS.startPlayer = async function (opts) {
        const root = document.getElementById('player-root');
        const shell = document.getElementById('player-shell');
        const wm = document.getElementById('player-watermark');
        const frame = document.getElementById('player-frame');
        const status = document.getElementById('player-status');
        const fsBtn = document.getElementById('btn-fullscreen');

        function log(msg) { status.textContent = msg; }

        // Support pre-populated session (embed mode) or fetch from API (normal mode).
        let session = opts.session || null;

        if (!session) {
            try {
                const resp = await fetch(opts.sessionEndpoint, {
                    method: 'POST',
                    headers: opts.antiForgery ? { 'RequestVerificationToken': opts.antiForgery } : {},
                    credentials: 'same-origin'
                });
                if (!resp.ok) { log('Access denied'); return; }
                session = await resp.json();
            } catch (e) { log('Network error'); return; }
        }

        // Privacy-safe display text (defense-in-depth — backend already returns a safe display string).
        const safeDisplay = maskSensitive(session.watermark.displayText);
        // Tiled grid uses "User · Session" (no timestamp). Strip any trailing HH:MM[:SS] off the display text.
        const gridText = maskSensitive(session.watermark.gridText
            || session.watermark.displayText.replace(/\s+\d{1,2}:\d{2}(:\d{2})?\s*$/, ''));

        // Install the tiled grid layer first (sits below the drifting spans).
        installGrid(shell, gridText);

        // Render the two drifting spans.
        startWatermark(wm, { displayText: safeDisplay });

        // Install the tamper guard (MutationObserver + sweep + self-healing).
        const guard = installTamperGuard(shell, safeDisplay, gridText, opts, session.sessionId);

        // NEVER set iframe src in attributes that get logged. Use direct property assignment.
        frame.src = session.embedUrl;

        // Heartbeats every 15s with visibility/focus/watermark/fullscreen state.
        const HB_MS = 15000;
        let lastPos = 0;
        const hbTimer = setInterval(() => {
            postEvent(opts.heartbeatEndpoint, {
                sessionId: session.sessionId,
                positionSeconds: lastPos,
                documentVisible: !document.hidden,
                documentFocused: document.hasFocus(),
                watermarkVisible: guard.isVisible(),
                fullscreen: !!document.fullscreenElement
            }, opts.antiForgery);
            lastPos += HB_MS / 1000;
        }, HB_MS);

        // App-level fullscreen on the SHELL (which contains watermark + grid + iframe), so
        // ESC-leaving fullscreen returns to the normal flow with overlays still intact.
        fsBtn.addEventListener('click', async () => {
            try {
                if (document.fullscreenElement) await document.exitFullscreen();
                else await shell.requestFullscreen({ navigationUI: 'hide' });
            } catch { /* gesture / permission errors — ignore */ }
        });
        document.addEventListener('fullscreenchange', () => {
            // Re-assert grid in case a vendor stylesheet or transition stripped it.
            installGrid(shell, gridText);
        });

        // Per-event-type debouncer for visibility/focus/devtools signals.
        const evDebounce = makeEventDebouncer(3000);

        document.addEventListener('visibilitychange', () => {
            const type = document.hidden ? 'VisibilityHidden' : 'Other';
            if (!evDebounce(type)) return;
            postEvent(opts.eventsEndpoint, {
                sessionId: session.sessionId,
                videoId: opts.videoId,
                type
            });
        });
        window.addEventListener('blur', () => {
            if (!evDebounce('FocusLost')) return;
            postEvent(opts.eventsEndpoint, { sessionId: session.sessionId, videoId: opts.videoId, type: 'FocusLost' });
        });

        // Naive devtools heuristic — reports only, never blocks.
        setInterval(() => {
            const dim = (window.outerWidth - window.innerWidth) > 200 || (window.outerHeight - window.innerHeight) > 250;
            if (dim && evDebounce('DevToolsOpen')) {
                postEvent(opts.eventsEndpoint, { sessionId: session.sessionId, videoId: opts.videoId, type: 'DevToolsOpen' });
            }
        }, 8000);

        // Disable right-click on the shell (cosmetic deterrent only).
        shell.addEventListener('contextmenu', e => e.preventDefault());

        // On unload, send a final event.
        window.addEventListener('beforeunload', () => {
            clearInterval(hbTimer);
            guard.stop();
            postEvent(opts.eventsEndpoint, { sessionId: session.sessionId, videoId: opts.videoId, type: 'Other', metadata: 'unload' });
        });
    };
})(window.VideoSecurity);
