import { defineConfig } from 'vitest/config';
import { stageSevenEvidence } from './tests/helpers/evidence.js';

export default defineConfig({
  test: {
    include: ['tests/integration/**/*.long.test.ts'],
    testTimeout: 75000,
    reporters: ['default', ['json', { outputFile: stageSevenEvidence('long.json') }]],
  },
});
