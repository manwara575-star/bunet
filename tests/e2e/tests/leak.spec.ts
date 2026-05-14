import { test, expect } from '@playwright/test';

/**
 * Leak gate E2E: anonymous-only assertions verifying that no protected
 * playback URLs / tokens leak to unauthenticated clients on any public surface.
 *
 * We do not authenticate here - integration tests cover the authenticated path.
 */

const LEAK_PATTERNS = ['.m3u8', '.mpd', 'iframe.mediadelivery.net', 'b-cdn.net'];

function assertNoLeaks(body: string) {
    for (const p of LEAK_PATTERNS) {
        expect(body, `response leaked pattern "${p}"`).not.toContain(p);
    }
}

test('GET /catalog without auth: redirects/401 and contains no leak patterns', async ({ request }) => {
    const r = await request.get('/catalog', { maxRedirects: 0, failOnStatusCode: false });
    expect([401, 302]).toContain(r.status());
    const body = await r.text();
    assertNoLeaks(body);
});

test('POST /api/videos/{id}/playback-session without auth: 401/302 and body has no embedUrl', async ({ request }) => {
    const r = await request.post('/api/videos/00000000-0000-0000-0000-000000000000/playback-session', {
        maxRedirects: 0,
        failOnStatusCode: false
    });
    expect([401, 302]).toContain(r.status());
    const body = await r.text();
    expect(body).not.toContain('embedUrl');
    assertNoLeaks(body);
});

test('GET /api/me/videos without auth: 401/302', async ({ request }) => {
    const r = await request.get('/api/me/videos', { maxRedirects: 0, failOnStatusCode: false });
    expect([401, 302]).toContain(r.status());
    const body = await r.text();
    assertNoLeaks(body);
});

test('GET /health/live: 200 with no leak patterns in body', async ({ request }) => {
    const r = await request.get('/health/live', { failOnStatusCode: false });
    expect(r.status()).toBe(200);
    const body = await r.text();
    assertNoLeaks(body);
});

test('CSP frame-src only allows iframe.mediadelivery.net (no raw b-cdn.net)', async ({ request }) => {
    const r = await request.get('/');
    const csp = r.headers()['content-security-policy'] || '';
    expect(csp).toContain('frame-src');
    expect(csp).toContain('iframe.mediadelivery.net');

    // Extract the frame-src directive only and assert b-cdn.net is not in it.
    const match = csp.split(';').map(s => s.trim()).find(d => d.startsWith('frame-src'));
    expect(match, 'frame-src directive must exist').toBeTruthy();
    expect(match!).not.toContain('b-cdn.net');
});
