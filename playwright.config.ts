import { defineConfig, devices } from '@playwright/test';
import { stageSevenEvidence } from './tests/helpers/evidence.js';

import { resolve } from 'node:path';

process.env['ST_E2E_DATA_DIR'] ??= resolve('runtime/e2e-stage7-' + Date.now());

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: [['list'], ['json', { outputFile: stageSevenEvidence('playwright.json') }]],
  use: {
    baseURL: 'https://localhost:8443',
    trace: 'retain-on-failure',
    ...devices['Desktop Edge'],
    channel: 'msedge',
  },
  webServer: {
    command: 'npm run start',
    env: {
      ST_DATA_DIR: process.env['ST_E2E_DATA_DIR'],
      ST_BANDWIDTH_POLICY: JSON.stringify({ ordinary: 16 * 1024 * 1024 }),
    },
    port: 8443,
    reuseExistingServer: false,
    timeout: 30000,
  },
});
