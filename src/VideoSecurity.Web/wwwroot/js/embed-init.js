(function () {
    'use strict';

    var root = document.getElementById('player-root');
    if (!root || !window.VideoSecurity) return;

    var sessionData = JSON.parse(root.dataset.embedSession);

    VideoSecurity.startPlayer({
        videoId: root.dataset.videoId,
        session: sessionData,
        heartbeatEndpoint: root.dataset.heartbeatEndpoint,
        eventsEndpoint: root.dataset.eventsEndpoint,
        antiForgery: ''
    });
})();
