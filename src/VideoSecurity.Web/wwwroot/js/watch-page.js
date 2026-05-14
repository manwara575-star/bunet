(function () {
    'use strict';

    const root = document.getElementById('player-root');
    if (!root || !window.VideoSecurity) return;

    VideoSecurity.startPlayer({
        videoId: root.dataset.videoId,
        sessionEndpoint: root.dataset.sessionEndpoint,
        heartbeatEndpoint: root.dataset.heartbeatEndpoint,
        eventsEndpoint: root.dataset.eventsEndpoint,
        antiForgery: document.querySelector('input[name="__RequestVerificationToken"]')?.value || ''
    });
})();
