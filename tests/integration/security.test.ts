import { once } from 'node:events';
import { request } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import {
  readFileSync,
  readdirSync,
  writeFileSync,
  mkdirSync,
  symlinkSync,
  unlinkSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  MESSAGE_TYPES as T,
  encodeMessage,
  decodeMessage,
  validateClientRequest,
} from '@securetransfer/protocol';
import { AuditLogger } from '../../apps/server/src/security/audit.js';
import { createApp } from '../../apps/server/src/app.js';
import { PROJECT_ROOT } from '../../apps/server/src/config.js';
import { openStore } from '../../apps/server/src/database/store.js';
import { testRuntime } from '../helpers/runtime.js';
import { createUser, rpc, probe, startTransport } from '../helpers/wss.js';

const ca = readFileSync(join(PROJECT_ROOT, 'runtime/certs/ca-cert.pem'));
const matrix: { check: string; result: 'PASS' }[] = [];
afterAll(() =>
  writeFileSync('docs/evidence/stage-7/security-matrix.json', JSON.stringify(matrix, null, 2)),
);
function http(port: number, path = '/api/health', options: Record<string, unknown> = {}) {
  return new Promise<{
    status: number;
    body: string;
    headers: import('node:http').IncomingHttpHeaders;
  }>((resolve, reject) => {
    const req = request({ hostname: 'localhost', port, path, ca, ...options }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        body += chunk;
      });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body, headers: res.headers }));
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('HTTP fixture timeout')));
    req.end();
  });
}
function portOf(server: import('node:https').Server) {
  return (server.address() as import('node:net').AddressInfo).port;
}

describe('stage-five security controls', () => {
  it('sends restrictive browser headers while preserving the real application', async () => {
    const app = await startTransport();
    try {
      const result = await http(portOf(app.server), '/');
      expect(result.status).toBe(200);
      expect(result.headers['content-security-policy']).toContain("frame-ancestors 'none'");
      expect(result.headers['content-security-policy']).toContain("worker-src 'self'");
      expect(result.headers['x-content-type-options']).toBe('nosniff');
      expect(result.headers['referrer-policy']).toBe('no-referrer');
      expect(result.headers['cache-control']).toBe('no-store');
      expect(result.body).toContain('<div id="app"></div>');
      matrix.push({ check: 'HTTP security headers and normal page', result: 'PASS' });
    } finally {
      await app.stop();
    }
  });
  it('rejects TLS 1.2 and a hostname mismatch without disabling certificate checks', async () => {
    const app = await startTransport();
    try {
      await expect(
        http(portOf(app.server), '/', { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }),
      ).rejects.toThrow();
      await expect(
        http(portOf(app.server), '/', { servername: 'wrong-host.invalid' }),
      ).rejects.toMatchObject({ code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
      expect((await http(portOf(app.server))).status).toBe(200);
      matrix.push({ check: 'Old TLS version and hostname rejection', result: 'PASS' });
    } finally {
      await app.stop();
    }
  });
  it('rejects an expired certificate signed by the otherwise trusted test CA', async () => {
    const runtime = testRuntime();
    const git = execFileSync('where.exe', ['git'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0]!;
    const openssl = resolve(dirname(git), '../usr/bin/openssl.exe');
    const expired = join(runtime.config.dataRoot, 'expired-cert.pem');
    execFileSync(
      openssl,
      [
        'x509',
        '-req',
        '-in',
        join(PROJECT_ROOT, 'runtime/certs/server.csr'),
        '-CA',
        join(PROJECT_ROOT, 'runtime/certs/ca-cert.pem'),
        '-CAkey',
        join(PROJECT_ROOT, 'runtime/certs/ca-key.pem'),
        '-set_serial',
        '555001',
        '-days',
        '0',
        '-extfile',
        join(PROJECT_ROOT, 'runtime/certs/server.ext'),
        '-out',
        expired,
      ],
      { stdio: 'pipe' },
    );
    await delay(1100);
    const server = await createApp(
      { ...runtime.config, certificatePath: expired },
      { onEvent: () => {} },
    );
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      await expect(http(portOf(server))).rejects.toMatchObject({ code: 'CERT_HAS_EXPIRED' });
      matrix.push({ check: 'Expired but CA-signed certificate rejected', result: 'PASS' });
    } finally {
      server.shutdownWebSockets();
      server.closeAllConnections();
      await new Promise<void>((done) => server.close(() => done()));
      await server.resourcesClosed;
      runtime.cleanup();
    }
  });
  it('rotates three bounded audit files and drops unknown sensitive fields', () => {
    const runtime = testRuntime();
    try {
      const audit = new AuditLogger(runtime.config.dataRoot, 1024);
      const marker = 'never-record-credential-fixture';
      for (let n = 0; n < 80; n++) {
        audit.write({
          event: 'security_fixture',
          requestId: n,
          connectionId: '10000000-0000-4000-8000-000000000001',
          ...{ password: marker, token: marker, payload: marker, path: marker },
        });
      }
      const paths = readdirSync(join(runtime.config.dataRoot, 'logs'));
      expect(paths.sort()).toEqual(['audit.1.jsonl', 'audit.2.jsonl', 'audit.jsonl']);
      for (const name of paths) {
        const content = readFileSync(join(runtime.config.dataRoot, 'logs', name), 'utf8');
        expect(Buffer.byteLength(content)).toBeLessThanOrEqual(1024);
        expect(content).not.toContain(marker);
        for (const line of content.trim().split('\n'))
          expect(JSON.parse(line)).toHaveProperty('timestamp');
      }
      matrix.push({ check: 'Audit rotation and field allowlist', result: 'PASS' });
    } finally {
      runtime.cleanup();
    }
  });
  it('records real security outcomes without password or session token contents', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const session = await createUser(ws, 'audit_user');
      const fileId = '10000000-0000-4000-8000-000000000001';
      expect((await rpc(ws, T.DELETE_FILE, { fileId })).json?.['code']).toBe('FILE_NOT_FOUND');
      await rpc(ws, T.LOGOUT);
      const content = readFileSync(join(app.dataRoot, 'logs/audit.jsonl'), 'utf8');
      expect(content).toContain('"event":"registered"');
      expect(content).toContain('"event":"authenticated"');
      expect(content).toContain('"errorCode":"FILE_NOT_FOUND"');
      expect(content).toContain('"event":"logged_out"');
      expect(content).not.toContain('fixture-stage-three');
      expect(content).not.toContain(String(session['token']));
      expect(content).not.toContain('"password"');
      matrix.push({ check: 'Authentication/access audit redaction', result: 'PASS' });
    } finally {
      await app.stop();
    }
  });
  it('fails closed for protected operations when audit storage stops working', async () => {
    const app = await startTransport();
    const silence = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const ws = app.connect();
      await once(ws, 'open');
      await createUser(ws);
      const path = join(app.dataRoot, 'logs/audit.jsonl');
      unlinkSync(path);
      mkdirSync(path);
      await http(portOf(app.server), '/', { method: 'POST' });
      expect((await http(portOf(app.server))).status).toBe(503);
      const closed = once(ws, 'close');
      ws.send(encodeMessage(T.PROBE, 600, { sequence: 1 }));
      expect((await closed)[0]).toBe(1011);
      const other = app.connect();
      const [, response] = await once(other, 'unexpected-response');
      expect(response.statusCode).toBe(503);
      response.resume();
      other.terminate();
      matrix.push({ check: 'Audit storage failure rejects protected operations', result: 'PASS' });
    } finally {
      await app.stop();
      silence.mockRestore();
    }
  });
  it('blocks a static-directory junction escaping the allowed web root', async () => {
    const runtime = testRuntime();
    const webRoot = join(runtime.config.dataRoot, 'web'),
      outside = join(runtime.config.dataRoot, 'outside');
    mkdirSync(webRoot);
    mkdirSync(outside);
    writeFileSync(join(outside, 'fixture.txt'), 'outside-static-fixture');
    symlinkSync(outside, join(webRoot, 'escape'), 'junction');
    const server = await createApp({ ...runtime.config, webRoot }, { onEvent: () => {} });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const result = await http(portOf(server), '/escape/fixture.txt');
      expect(result.status).toBe(404);
      expect(result.body).not.toContain('outside-static-fixture');
      matrix.push({ check: 'Static junction escape denied', result: 'PASS' });
    } finally {
      server.shutdownWebSockets();
      server.closeAllConnections();
      await new Promise<void>((done) => server.close(() => done()));
      await server.resourcesClosed;
      runtime.cleanup();
    }
  });
  it('refuses a storage junction instead of treating it as an authorized file', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const user = await createUser(ws);
      const outside = join(app.dataRoot, 'outside');
      mkdirSync(outside);
      const id = '10000000-0000-4000-8000-000000000001';
      symlinkSync(outside, join(app.dataRoot, 'storage', id), 'junction');
      const db = openStore(app.dataRoot);
      try {
        db.prepare('INSERT INTO files VALUES (?, ?, ?, ?, ?, ?)').run(
          id,
          String(user['userId']),
          'linked.txt',
          0,
          '0'.repeat(64),
          new Date().toISOString(),
        );
      } finally {
        db.close();
      }
      expect((await rpc(ws, T.DOWNLOAD_INIT, { fileId: id })).json?.['code']).toBe('FORBIDDEN');
      expect((await rpc(ws, T.DELETE_FILE, { fileId: id })).json?.['code']).toBe('FORBIDDEN');
      matrix.push({ check: 'Storage junction denied before file access', result: 'PASS' });
    } finally {
      await app.stop();
    }
  });
  it('keeps a normal connection responsive after excess TCP connections are dropped', async () => {
    const app = await startTransport();
    app.server.maxConnections = 3;
    try {
      const clients = [];
      for (let n = 0; n < 3; n++) {
        const ws = app.connect();
        await once(ws, 'open');
        clients.push(ws);
      }
      const rejected = app.connect();
      expect((await once(rejected, 'error'))[0]).toBeInstanceOf(Error);
      expect((await probe(clients[0]!, 1)).json?.['sequence']).toBe(1);
      clients[1]!.close();
      await once(clients[1]!, 'close');
      await delay(20);
      const recovered = app.connect();
      await once(recovered, 'open');
      expect((await probe(recovered, 2)).json?.['sequence']).toBe(2);
      matrix.push({ check: 'Connection cap and continued normal service', result: 'PASS' });
    } finally {
      await app.stop();
    }
  });
  it('rejects oversized HTTP headers without recording their contents', async () => {
    const app = await startTransport();
    try {
      const socket = tlsConnect({ host: 'localhost', port: portOf(app.server), ca });
      await once(socket, 'secureConnect');
      let body = '';
      socket.setEncoding('utf8');
      socket.on('data', (chunk: string) => {
        body += chunk;
      });
      const closed = once(socket, 'close');
      socket.write(
        'GET / HTTP/1.1\r\nHost: localhost\r\nX-Fixture: ' + 'x'.repeat(20000) + '\r\n\r\n',
      );
      await closed;
      expect(body).toContain('400 Bad Request');
      expect((await http(portOf(app.server))).status).toBe(200);
      const log = readFileSync(join(app.dataRoot, 'logs/audit.jsonl'), 'utf8');
      expect(log).toContain('http_parser_rejected');
      expect(log).not.toContain('x'.repeat(100));
      matrix.push({ check: 'HTTP header cap and parser audit redaction', result: 'PASS' });
    } finally {
      await app.stop();
    }
  });
  it.each([
    '../file',
    'C:\\file',
    '\\\\server\\share',
    'file:stream',
    'bad?.txt',
    'CON .txt',
    '..',
    'trailing.',
    'trailing ',
  ])('rejects unsafe or reserved display filename %s', (name) => {
    const packet = decodeMessage(
      encodeMessage(T.UPLOAD_INIT, 1, { name, size: 0, sha256: '0'.repeat(64) }),
    );
    expect(() => validateClientRequest(packet, 'AUTHENTICATED')).toThrow();
  });
});

it('waits for WSS close auditing before releasing a fixture runtime', async () => {
  const monitor = vi.spyOn(console, 'error').mockImplementation(() => {});
  const app = await startTransport();
  try {
    const ws = app.connect();
    await once(ws, 'open');
    await probe(ws, 1);
    await app.stop();
    await delay(20);
    expect(monitor).not.toHaveBeenCalled();
    matrix.push({ check: 'WSS shutdown audit lifecycle', result: 'PASS' });
  } finally {
    monitor.mockRestore();
  }
});

it('enforces the default unauthenticated connection cap and then accepts a new connection', async () => {
  const app = await startTransport();
  try {
    const clients = [];
    for (let n = 0; n < 5; n++) {
      const ws = app.connect();
      await once(ws, 'open');
      clients.push(ws);
    }
    const excess = app.connect();
    const [, response] = await once(excess, 'unexpected-response');
    expect(response.statusCode).toBe(503);
    response.resume();
    excess.terminate();
    clients[0]!.close();
    await once(clients[0]!, 'close');
    await delay(20);
    const recovered = app.connect();
    await once(recovered, 'open');
    expect((await probe(recovered, 1)).json?.['sequence']).toBe(1);
    matrix.push({ check: 'Default unauthenticated cap and recovery', result: 'PASS' });
  } finally {
    await app.stop();
  }
});

it.each(['idle', 'partial'])(
  'closes a %s TLS client without poisoning browser connection reuse',
  async (mode) => {
    const app = await startTransport();
    app.server.headersTimeout = 100;
    app.server.requestTimeout = 1000;
    try {
      const socket = tlsConnect({ host: 'localhost', port: portOf(app.server), ca });
      await once(socket, 'secureConnect');
      let body = '';
      socket.setEncoding('utf8');
      socket.on('data', (chunk: string) => {
        body += chunk;
      });
      const closed = once(socket, 'close');
      const timer = setTimeout(
        () => socket.destroy(new Error('Slow-header timeout not enforced')),
        5000,
      );
      if (mode === 'partial') socket.write('GET / HTTP/1.1\r\nHost: localhost\r\n');
      try {
        await closed;
      } finally {
        clearTimeout(timer);
      }
      expect(body).toBe('');
      expect((await http(portOf(app.server))).status).toBe(200);
      matrix.push({
        check:
          mode === 'partial'
            ? 'Bounded slow-header cleanup'
            : 'Idle preconnection cleanup without unsolicited response',
        result: 'PASS',
      });
    } finally {
      await app.stop();
    }
  },
);
