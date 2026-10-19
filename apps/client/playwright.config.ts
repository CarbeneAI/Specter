import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/markdown',
  testMatch: '*.spec.ts',
  workers: 1,
  retries: 0,
  use: { browserName: 'chromium', baseURL: 'http://127.0.0.1:4179', serviceWorkers: 'block' },
  webServer: {
    command: 'bun --no-env-file x vite --config tests/markdown/vite.config.ts',
    url: 'http://127.0.0.1:4179/tests/markdown/fixture.html',
    reuseExistingServer: false,
  },
});
