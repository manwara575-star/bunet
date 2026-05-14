/// <reference types="node" />

import { test, expect, Page } from '@playwright/test';

/**
 * Authenticated leak coverage. Each route runs in its own page context
 * (Playwright creates a fresh context per test by default), so the suite is
 * parallel-safe.
 *
 * Authentication is supplied by the `auth` project (see playwright.config.ts),
 * which loads the storageState written by global-setup.ts. The spec itself
 * never logs in, so each test is independent.
 *
 * We watch every response (XHR/fetch/document) and assert that no body or the
 * final rendered HTML contains a raw playback URL, Bunny CDN host, embed iframe
 * URL, or an `embedUrl` JSON field.
 */

const LEAK_PATTERNS: RegExp[] = [
    /\.m3u8/i,
    /\.mpd/i,
    /\bb-cdn\.net\b/i,
    /iframe\.mediadelivery\.net/i,
    /"embedUrl"\s*:/i
];

const ROUTES = [
    '/catalog',
    '/admin',
    '/admin/policies',
    '/admin/keys',
    '/admin/audit',
    '/admin/roles',
    '/health/ready'
];

function attachLeakWatcher(page: Page, label: string): string[] {
    const leaks: string[] = [];
    page.on('response', async resp => {
        const ct = resp.headers()['content-type'] ?? '';
        if (!/text|json|xml|html|javascript/i.test(ct)) return;
        let body = '';
        try {
            body = await resp.text();
        } catch {
            return;
        }
        for (const re of LEAK_PATTERNS) {
            if (re.test(body)) {
                leaks.push(`${label} ${resp.url()} :: ${re}`);
            }
        }
    });
    return leaks;
}

for (const route of ROUTES) {
    test(`authenticated ${route} has no raw video URL leak`, async ({ page }) => {
        const leaks = attachLeakWatcher(page, route);

        const resp = await page.goto(route, { waitUntil: 'networkidle' });
        const status = resp?.status() ?? 0;

        // Routes that 404 belong to an Admin UI surface that may not have
        // landed yet on partial deploys. Skip cleanly so the suite still
        // protects deployed surfaces.
        test.skip(status === 404, `${route} not present (404)`);

        // Authenticated probes should not be redirected to login.
        expect(
            page.url().includes('/Identity/Account/Login'),
            `${route} bounced to login - storage state likely failed`
        ).toBe(false);

        // Drain in-flight body reads triggered by 'response' handlers.
        await page.waitForLoadState('networkidle').catch(() => undefined);

        expect(leaks, `Network body leaks on ${route}:\n${leaks.join('\n')}`).toEqual([]);

        const html = await page.content();
        for (const re of LEAK_PATTERNS) {
            expect(html, `Rendered HTML leaked ${re} on ${route}`).not.toMatch(re);
        }
    });
}
