import { chromium, FullConfig, request } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

/**
 * Global setup: log the seeded CI admin in once and persist storage state for
 * the `auth` Playwright project. Anonymous tests do not load this state.
 */
export default async function globalSetup(config: FullConfig) {
    const baseURL =
        config.projects[0]?.use?.baseURL ||
        process.env.BASE_URL ||
        'http://127.0.0.1:5000';

    const email = process.env.E2E_ADMIN_EMAIL || process.env.Seed__AdminEmail || 'ci@example.com';
    const password = process.env.E2E_ADMIN_PASSWORD || process.env.Seed__AdminPassword || 'Ci-Test-PasswordWithStrength!1234';

    const authDir = path.join(__dirname, '.auth');
    const storageStatePath = path.join(authDir, 'admin.json');
    fs.mkdirSync(authDir, { recursive: true });

    // Wait briefly for the .NET app to be ready (webServer.url already gates on this,
    // but globalSetup runs before some of that on cold starts in CI).
    const ready = await waitForReady(baseURL, 60_000);
    if (!ready) {
        throw new Error(`global-setup: app at ${baseURL} did not become ready in time`);
    }

    const browser = await chromium.launch();
    const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
    const page = await context.newPage();
    try {
        await page.goto('/Identity/Account/Login', { waitUntil: 'domcontentloaded' });

        const emailInput = page.locator('input[name="Input.Email"]');
        const passwordInput = page.locator('input[name="Input.Password"]');
        await emailInput.waitFor({ state: 'visible', timeout: 15_000 });
        await emailInput.fill(email);
        await passwordInput.fill(password);

        await Promise.all([
            page.waitForLoadState('networkidle'),
            page.locator('button[type="submit"], input[type="submit"]').first().click()
        ]);

        // Sanity check: the login page should no longer be rendered, OR an error summary
        // should NOT be visible. Probe a known authenticated endpoint.
        const probe = await context.request.get('/api/me/videos', { failOnStatusCode: false });
        if (probe.status() === 401 || probe.status() === 403) {
            const html = await page.content();
            const hint = html.includes('validation-summary-errors') ? ' (validation errors present on login page)' : '';
            throw new Error(
                `global-setup: login as ${email} failed${hint}. /api/me/videos returned ${probe.status()}.`
            );
        }

        await context.storageState({ path: storageStatePath });
    } finally {
        await context.close();
        await browser.close();
    }
}

async function waitForReady(baseURL: string, timeoutMs: number): Promise<boolean> {
    const ctx = await request.newContext({ baseURL, ignoreHTTPSErrors: true });
    const deadline = Date.now() + timeoutMs;
    try {
        while (Date.now() < deadline) {
            try {
                const r = await ctx.get('/health/live', { failOnStatusCode: false, timeout: 5_000 });
                if (r.status() === 200) return true;
            } catch {
                /* swallow until timeout */
            }
            await new Promise(res => setTimeout(res, 1_000));
        }
        return false;
    } finally {
        await ctx.dispose();
    }
}
