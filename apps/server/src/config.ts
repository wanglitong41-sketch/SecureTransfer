import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { readBandwidthPolicy } from './transfer/flow-control.js';

export const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const port = Number(env['ST_PORT'] ?? 8443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('ST_PORT must be an integer from 1 to 65535');
  }
  const runtimeRoot = join(PROJECT_ROOT, 'runtime');
  return {
    bandwidth: readBandwidthPolicy(env['ST_BANDWIDTH_POLICY']),
    host: '127.0.0.1',
    development: env['ST_MODE'] === 'development',
    port,
    dataRoot: resolve(env['ST_DATA_DIR'] ?? runtimeRoot),
    certificatePath: join(runtimeRoot, 'certs', 'server-cert.pem'),
    keyPath: join(runtimeRoot, 'certs', 'server-key.pem'),
    webRoot: join(PROJECT_ROOT, 'apps', 'web', 'dist'),
  };
}

export type ServerConfig = ReturnType<typeof loadConfig>;
