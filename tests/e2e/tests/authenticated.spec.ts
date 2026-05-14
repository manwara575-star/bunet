/// <reference types="node" />

import { test, expect } from '@playwright/test';

const email = process.env.E2E_ADMIN_EMAIL || process.env.Seed__AdminEmail || 'ci@example.com';
const password = process.env.E2E_ADMIN_PASSWORD || process.env.Seed__AdminPassword || 'Ci-Test-PasswordWithStrength!1234';

const LEAK_PATTERNS = ['.m3u8', '.mpd', '.mp4', 'b-cdn.net'];

function assertNoRawVideoLeaks(body: string) {
    for (const pattern of LEAK_PATTERNS) {
        expect(body, `authenticated response leaked pattern "${pattern}"`).not.toContain(pattern);
    }
}

test('admin can sign in and dashboard still contains no raw video URLs', async ({ page }) => {
    await page.goto('/Identity/Account/Login');
    await page.getByLabel(/email/i).fill(email);
    await page.getByLabel(/password/i).fill(password);
    await page.getByRole('button', { name: /log in/i }).click();

    const response = await page.goto('/admin');
    expect(response?.status()).toBe(200);
    await expect(page).toHaveURL(/\/admin$/);
    assertNoRawVideoLeaks(await page.content());
});

test('authenticated playback session does not leak raw media URLs', async ({ page, baseURL }) => {
    await page.route('https://iframe.mediadelivery.net/**', route => route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<!doctype html><title>stub player</title>'
    }));

    const sameOriginBodies: Promise<string>[] = [];
    page.on('response', response => {
        if (!response.url().startsWith(baseURL ?? '')) return;
        const contentType = response.headers()['content-type'] ?? '';
        if (!/(text|json|javascript|html|css)/i.test(contentType)) return;
        sameOriginBodies.push(response.text().catch(() => ''));
    });

    await page.goto('/Identity/Account/Login');
    await page.getByLabel(/email/i).fill(email);
    await page.getByLabel(/password/i).fill(password);
    await page.getByRole('button', { name: /log in/i }).click();
    await expect(page).toHaveURL(/\/$/);

    const videosResponse = await page.request.get('/api/me/videos');
    expect(videosResponse.status()).toBe(200);
    const videosBody = await videosResponse.text();
    assertNoRawVideoLeaks(videosBody);
    const videos = JSON.parse(videosBody) as Array<{ id: string; title: string }>;
    const seededVideo = videos.find(video => video.title === 'E2E Ready Video');
    expect(seededVideo, 'seeded ready video should be visible to the admin user').toBeTruthy();

    const sessionResponsePromise = page.waitForResponse(response =>
        response.url().includes(`/api/videos/${seededVideo!.id}/playback-session`) && response.request().method() === 'POST');
    await page.goto(`/player/watch/${seededVideo!.id}`);
    const sessionResponse = await sessionResponsePromise;
    expect(sessionResponse.status()).toBe(200);
    const sessionBody = await sessionResponse.text();
    assertNoRawVideoLeaks(sessionBody);
    expect(sessionBody).toContain('iframe.mediadelivery.net');

    await expect(page.locator('#player-frame')).toHaveAttribute('src', /iframe\.mediadelivery\.net/);
    assertNoRawVideoLeaks(await page.content());

    const browserState = await page.evaluate(() => JSON.stringify({
        localStorage: { ...window.localStorage },
        sessionStorage: { ...window.sessionStorage },
        frameSrc: document.getElementById('player-frame')?.getAttribute('src')
    }));
    assertNoRawVideoLeaks(browserState);

    for (const body of await Promise.all(sameOriginBodies)) {
        assertNoRawVideoLeaks(body);
    }
});
