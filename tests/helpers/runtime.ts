import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { loadConfig, PROJECT_ROOT } from '../../apps/server/src/config.js';

export function testRuntime() {
  const runtime = resolve(PROJECT_ROOT, 'runtime');
  mkdirSync(runtime, { recursive: true });
  const directory = mkdtempSync(join(runtime, 'test-stage3-'));
  return {
    config: { ...loadConfig(), dataRoot: directory },
    cleanup() {
      const location = relative(runtime, resolve(directory));
      if (!location || location.startsWith('..') || isAbsolute(location))
        throw new Error('Invalid test cleanup path');
      rmSync(directory, { recursive: true, force: true });
    },
  };
}
