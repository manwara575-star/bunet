/// <reference types="node" />

import { defineConfig } from '@playwright/test';
import * as path from 'path';

const BASE_URL = process.env.BASE_URL || 'http://127.0.0.1:5000';

const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL || process.env.Seed__AdminEmail || 'ci@example.com';
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || process.env.Seed__AdminPassword || 'Ci-Test-PasswordWithStrength!1234';

export const ADMIN_STORAGE_STATE = path.join(__dirname, '.auth', 'admin.json');

export default defineConfig({
    testDir: './tests',
    timeout: 30_000,
    fullyParallel: true,
    workers: process.env.CI ? 2 : undefined,
    globalSetup: require.resolve('./global-setup'),
    use: {
        baseURL: BASE_URL,
        ignoreHTTPSErrors: true,
        trace: 'on-first-retry'
    },
    projects: [
        {
            // Anonymous suites: smoke + leak. Excludes auth-leak so it doesn't
            // run twice without storage state.
            name: 'chromium',
            use: { browserName: 'chromium' },
            testIgnore: /auth-leak\.spec\.ts/
        },
        {
            // Authenticated suite: only auth-leak.spec.ts, with the storage
            // state written by global-setup.ts.
            name: 'auth',
            use: {
                browserName: 'chromium',
                storageState: ADMIN_STORAGE_STATE
            },
            testMatch: /auth-leak\.spec\.ts/
        }
    ],
    webServer: process.env.SKIP_WEBSERVER ? undefined : {
        command: `dotnet run --project ../../src/VideoSecurity.Web --urls ${BASE_URL}`,
        url: BASE_URL,
        env: {
            ...process.env,
            ASPNETCORE_ENVIRONMENT: process.env.ASPNETCORE_ENVIRONMENT || 'Development',
            Hosting__DisableHttpsRedirection: 'true',
            Hosting__AllowInsecureCookies: 'true',
            Bunny__LibraryId: process.env.Bunny__LibraryId || process.env.BUNNY_LIBRARY_ID || '12345',
            Bunny__ApiKey: process.env.Bunny__ApiKey || process.env.BUNNY_API_KEY || 'ci-bunny-api-key-for-tests-only-32chars!',
            Bunny__EmbedTokenKey: process.env.Bunny__EmbedTokenKey || process.env.BUNNY_EMBED_TOKEN_KEY || 'ci-embed-token-key-for-tests-only-32chrs',
            Bunny__CdnHostname: process.env.Bunny__CdnHostname || process.env.BUNNY_CDN_HOSTNAME || 'vz-citest-e2e.b-cdn.net',
            Bunny__PrivacyHashPepper: process.env.Bunny__PrivacyHashPepper || 'ci-pepper-do-not-use-in-prod-32-chars-min',
            Bunny__WebhookSecret: process.env.Bunny__WebhookSecret || process.env.BUNNY_WEBHOOK_SECRET || 'ci-webhook-secret-for-tests-only-32-chrs',
            Seed__AdminEmail: ADMIN_EMAIL,
            Seed__AdminPassword: ADMIN_PASSWORD,
            Seed__E2EReadyVideo: process.env.Seed__E2EReadyVideo || 'true',
            Seed__E2EReadyVideoBunnyId: process.env.Seed__E2EReadyVideoBunnyId || 'e2e-ready-video',
            Seed__E2EReadyVideoTitle: process.env.Seed__E2EReadyVideoTitle || 'E2E Ready Video'
        },
        reuseExistingServer: false,
        timeout: 180_000,
        ignoreHTTPSErrors: true
    }
});
