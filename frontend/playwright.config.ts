// The browser journey (ADR-0094 item 4): Chromium against the built interface,
// the real API, its worker and PostgreSQL, all offline.  The tests do not start
// the API: scripts/check_browser_e2e.sh does (a new database, the offline
// profile, the seeded refused report), then runs them with E2E_BASE_URL.
// Run that script, not `npx playwright test` alone.
import { defineConfig, devices } from '@playwright/test'

const CI = !!process.env.CI

export default defineConfig({
  testDir: './e2e',
  // Each journey works on reports of its own, so they run side by side; the
  // API's worker runs up to three reports at once (WORKER_MAX_CONCURRENT=3 in
  // scripts/check_browser_e2e.sh), one per Playwright worker.
  fullyParallel: true,
  workers: 3,
  forbidOnly: CI,
  // A journey that passes only on a second try is a failure to look at.
  retries: 0,
  // Bounds, not pauses: one journey, the whole run, one expectation.
  timeout: 180_000,
  globalTimeout: 15 * 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:8765',
    // Kept for a failed journey only (frontend/test-results, playwright-report).
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    acceptDownloads: true,
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
  // A 1440×900 laptop screen: at 720 px the review page's relationship rail
  // covers much of the entity margin.
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } }],
})
