import { test, expect } from '@playwright/test';

/**
 * Smoke E2E: verifies the public surface does NOT leak protected URLs.
 * (We do NOT log in here — protected playback is asserted by integration tests.)
 */
test('home page renders and contains no Bunny URLs', async ({ page }) => {
    const resp = await page.goto('/');
    expect(resp?.status()).toBe(200);
    const body = await page.content();
    expect(body).not.toContain('.m3u8');
    expect(body).not.toContain('.mpd');
    expect(body).not.toContain('iframe.mediadelivery.net');
    expect(body).not.toContain('b-cdn.net');
    expect(body).not.toContain('embedUrl');
    expect(body).not.toContain('playbackSessionId');
});

test('security headers are present', async ({ request }) => {
    const r = await request.get('/');
    expect(r.headers()['permissions-policy'] || '').toContain('display-capture=()');
    expect(r.headers()['content-security-policy'] || '').toContain('frame-src https://iframe.mediadelivery.net');
    expect(r.headers()['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(r.headers()['x-content-type-options']).toBe('nosniff');
});

test('unauthenticated playback-session returns 401 or redirect', async ({ request }) => {
    const r = await request.post('/api/videos/00000000-0000-0000-0000-000000000000/playback-session', {
        maxRedirects: 0,
        failOnStatusCode: false
    });
    expect([401, 302]).toContain(r.status());
});
