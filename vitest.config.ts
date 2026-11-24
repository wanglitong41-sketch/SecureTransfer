import { defineConfig } from 'vitest/config';
import { stageSevenEvidence } from './tests/helpers/evidence.js';

export default defineConfig({
  test: {
    include: ['tests/integration/**/*.test.ts', 'packages/**/*.test.ts', 'apps/**/*.test.ts'],
    exclude: ['tests/integration/**/*.long.test.ts'],
    testTimeout: 10000,
    reporters: ['default', ['json', { outputFile: stageSevenEvidence('vitest.json') }]],
  },
});
