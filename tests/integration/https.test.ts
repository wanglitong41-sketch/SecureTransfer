import { request } from 'node:https';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:https';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { testRuntime } from '../helpers/runtime.js';
import { createApp } from '../../apps/server/src/app.js';
import { PROJECT_ROOT } from '../../apps/server/src/config.js';

const runtime = testRuntime();
let server: Server & { resourcesClosed: Promise<void> };
let port: number;
const ca = await readFile(join(PROJECT_ROOT, 'runtime/certs/ca-cert.pem'));

function get(path: string, trusted = true, method = 'GET') {
  return new Promise<{ status: number; body: string; tls: string | null }>((resolve, reject) => {
    const req = request(
      {
        hostname: 'localhost',
        port,
        path,
        method,
        ...(trusted ? { ca } : {}),
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body,
            tls:
              req.socket && 'getProtocol' in req.socket
                ? (req.socket as import('node:tls').TLSSocket).getProtocol()
                : null,
          }),
        );
      },
    );
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Test request timed out')));
    req.end();
  });
}

beforeAll(async () => {
  server = await createApp(runtime.config);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  port = (server.address() as AddressInfo).port;
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  await server.resourcesClosed;
  runtime.cleanup();
});

describe('HTTPS application bootstrap', () => {
  it('responds over TLS 1.3 using the expected CA', async () => {
    const result = await get('/api/health');
    expect(result.status).toBe(200);
    expect(result.tls).toBe('TLSv1.3');
    expect(JSON.parse(result.body)).toEqual({ status: 'ok', stage: 6, protocolVersion: 1 });
  });
  it('rejects an untrusted certificate', async () => {
    await expect(get('/api/health', false)).rejects.toThrow();
  });
  it('serves the built Vue entry page', async () => {
    const result = await get('/');
    expect(result.status).toBe(200);
    expect(result.body).toContain('<div id="app"></div>');
    expect(result.body).toContain('/assets/');
  });
  it.each([
    '/runtime/certs/server-key.pem',
    '/%2e%2e%5c%2e%2e%5cruntime/certs/server-key.pem',
    '/%ZZ',
  ])('does not expose paths outside web output: %s', async (path) => {
    const result = await get(path);
    expect([400, 404]).toContain(result.status);
    expect(result.body).not.toContain('PRIVATE KEY');
  });
  it('rejects unsupported methods', async () => {
    expect((await get('/api/health', true, 'POST')).status).toBe(405);
  });
});
