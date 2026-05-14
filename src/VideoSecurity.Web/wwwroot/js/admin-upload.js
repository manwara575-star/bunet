/* Admin TUS upload using server-issued credentials.
 * Per https://docs.bunny.net/stream/tus-resumable-uploads
 *
 * Flow:
 *   1) POST /api/admin/videos { title, ... } -> { videoId, bunnyVideoId, libraryId, upload: {tusEndpoint, sig, expire, ...} }
 *   2) tus.Upload(file, { endpoint, headers: { AuthorizationSignature, AuthorizationExpire, VideoId, LibraryId } })
 *
 * The browser never holds the Bunny library API key. The signature is single-use, time-limited,
 * and tied to the freshly-created videoId.
 */
(function () {
    const log = (msg) => {
        const el = document.getElementById('log');
        el.textContent += `\n[${new Date().toISOString()}] ${msg}`;
        el.scrollTop = el.scrollHeight;
    };

    document.getElementById('meta-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = document.getElementById('file').files[0];
        if (!file) return alert('Pick a file first.');

        const body = {
            title: document.getElementById('title').value.trim(),
            description: document.getElementById('description').value.trim() || null,
            courseId: document.getElementById('courseId').value.trim() || null,
            collectionId: document.getElementById('collectionId').value.trim() || null,
            fileName: file.name
        };
        const af = document.querySelector('input[name="__RequestVerificationToken"]').value;

        log('Creating Bunny video object...');
        const resp = await fetch('/api/admin/videos', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'RequestVerificationToken': af },
            body: JSON.stringify(body)
        });
        if (!resp.ok) { log('Create failed: ' + resp.status); return; }
        const created = await resp.json();
        log('Got upload credentials. Starting TUS to ' + created.upload.tusEndpoint);

        const upload = new tus.Upload(file, {
            endpoint: created.upload.tusEndpoint,
            retryDelays: [0, 1500, 3000, 7000, 12000],
            headers: {
                AuthorizationSignature: created.upload.authorizationSignature,
                AuthorizationExpire: String(created.upload.authorizationExpire),
                VideoId: created.upload.videoId,
                LibraryId: String(created.upload.libraryId)
            },
            metadata: {
                filetype: file.type,
                title: body.title,
                collection: body.collectionId || ''
            },
            chunkSize: 25 * 1024 * 1024,
            onError: (err) => log('TUS error: ' + err),
            onProgress: (b, t) => log(`Upload ${(b/t*100).toFixed(1)}%`),
            onSuccess: () => log('Upload complete. Bunny will now process the video.')
        });
        upload.start();
    });
})();
