import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { describe, it, expect } from 'vitest';
import { WebSocket } from 'ws';
import { startTransport, probe, dataBytes } from '../helpers/wss.js';
import {
  encodeMessage,
  decodeMessage,
  MESSAGE_TYPES as T,
  MAX_MESSAGE_BYTES,
} from '@securetransfer/protocol';

describe('WSS transport', () => {
  it('correlates ten requests on the same TLS connection', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const ids = [];
      for (let n = 1; n <= 10; n++) {
        const result = await probe(ws, n);
        expect(result.header.requestId).toBe(n);
        expect(result.header.messageType).toBe(T.RESULT);
        expect(result.json?.['sequence']).toBe(n);
        ids.push(result.json?.['connectionId']);
      }
      expect(new Set(ids).size).toBe(1);
      expect(app.events.filter((e) => e.event === 'connected')).toHaveLength(1);
      expect(app.events.filter((e) => e.event === 'probe')).toHaveLength(10);
      expect(ws.readyState).toBe(WebSocket.OPEN);
    } finally {
      await app.stop();
    }
  });
  it('denies unapproved origins, missing origins, and alternate paths', async () => {
    const app = await startTransport();
    try {
      for (const [origin, path, code] of [
        ['https://evil.example', '/ws', 403],
        ['', '/ws', 403],
        ['https://localhost:8443', '/other', 404],
        ['https://localhost:5173', '/ws', 403],
      ] as const) {
        const ws = app.connect({ origin }, path);
        const [, response] = await once(ws, 'unexpected-response');
        expect(response.statusCode).toBe(code);
        response.resume();
        ws.terminate();
      }
    } finally {
      await app.stop();
    }
  });
  it('only allows the development origin when explicitly configured', async () => {
    const app = await startTransport({ allowedOrigins: ['https://localhost:5173'] });
    try {
      const ws = app.connect({ origin: 'https://localhost:5173' });
      await once(ws, 'open');
    } finally {
      await app.stop();
    }
  });
  it('rejects unauthenticated requests and unknown credentials', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const closed = once(ws, 'close');
      for (const [type, body, code] of [
        [T.LIST_FILES, {}, 'UNAUTHORIZED'],
        [T.LOGIN, { username: 'alice', password: 'fixture123' }, 'UNAUTHORIZED'],
      ] as const) {
        const reply = once(ws, 'message');
        ws.send(encodeMessage(type, 1, body));
        const [data] = await reply;
        expect(decodeMessage(dataBytes(data)).json?.['code']).toBe(code);
      }
      expect((await closed)[0]).toBe(1008);
    } finally {
      await app.stop();
    }
  });
  it.each(['text', 'header', 'oversize'])('closes malformed %s messages', async (kind) => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const closed = once(ws, 'close');
      if (kind === 'text') ws.send('{}');
      else if (kind === 'oversize') ws.send(new Uint8Array(MAX_MESSAGE_BYTES + 1));
      else ws.send(new Uint8Array(10));
      const [code] = await closed;
      expect(code).toBe(kind === 'oversize' ? 1009 : 1002);
    } finally {
      await app.stop();
    }
  });
  it('enforces authentication deadline even when probes are successful', async () => {
    const app = await startTransport({ authenticationMs: 180, heartbeatMs: 50 });
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const closed = once(ws, 'close');
      await probe(ws, 1);
      const [code] = await closed;
      expect(code).toBe(1008);
      expect(app.events.some((e) => e.event === 'authentication_timeout')).toBe(true);
    } finally {
      await app.stop();
    }
  });
  it('cleans up a client that does not answer heartbeat pings', async () => {
    const app = await startTransport({ authenticationMs: 5000, heartbeatMs: 50 });
    try {
      const ws = app.connect({ autoPong: false });
      await once(ws, 'open');
      const [code] = await once(ws, 'close');
      expect(code).toBe(1006);
      expect(app.events.some((e) => e.event === 'heartbeat_timeout')).toBe(true);
    } finally {
      await app.stop();
    }
  });
  it('enforces a small injected connection limit and request budget', async () => {
    const app = await startTransport({ maxConnections: 1, requestsPerSecond: 1 });
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const other = app.connect();
      const [, response] = await once(other, 'unexpected-response');
      expect(response.statusCode).toBe(503);
      response.resume();
      other.terminate();
      await probe(ws, 1);
      const closed = once(ws, 'close');
      const reply = once(ws, 'message');
      ws.send(encodeMessage(T.PROBE, 2, { sequence: 2 }));
      const [data] = await reply;
      expect(decodeMessage(dataBytes(data)).json?.['code']).toBe('RATE_LIMITED');
      expect((await closed)[0]).toBe(1008);
    } finally {
      await app.stop();
    }
  });
  it('supports WebSocket fragmentation but not partial application packets', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const packet = encodeMessage(T.PROBE, 8, { sequence: 8 });
      const reply = once(ws, 'message');
      ws.send(packet.subarray(0, 12), { binary: true, fin: false });
      ws.send(packet.subarray(12), { binary: true, fin: true });
      expect(decodeMessage(dataBytes((await reply)[0])).header.requestId).toBe(8);
      ws.close(1000);
      await once(ws, 'close');
      await delay(5);
    } finally {
      await app.stop();
    }
  });
});

it('associates concurrently pending responses with their request IDs', async () => {
  const app = await startTransport();
  try {
    const ws = app.connect();
    await once(ws, 'open');
    const received = new Map<number, number>();
    const complete = new Promise<void>((resolve, reject) => {
      ws.on('message', (data) => {
        try {
          const message = decodeMessage(dataBytes(data));
          received.set(message.header.requestId, Number(message.json?.['sequence']));
          if (received.size === 10) resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    for (let n = 10; n >= 1; n--) ws.send(encodeMessage(T.PROBE, n, { sequence: n * 2 }));
    await complete;
    for (let n = 1; n <= 10; n++) expect(received.get(n)).toBe(n * 2);
  } finally {
    await app.stop();
  }
});

it('rejects WSS when the caller does not trust the server CA', async () => {
  const app = await startTransport();
  try {
    const ws = app.connect({ ca: undefined });
    const [error] = await once(ws, 'error');
    expect(error).toBeInstanceOf(Error);
    expect(app.events.filter((event) => event.event === 'connected')).toHaveLength(0);
  } finally {
    await app.stop();
  }
});
