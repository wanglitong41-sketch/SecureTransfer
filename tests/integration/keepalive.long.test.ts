import { once } from 'node:events';
import { stageSevenEvidence } from '../helpers/evidence.js';
import { setTimeout as delay } from 'node:timers/promises';
import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { MESSAGE_TYPES as T } from '@securetransfer/protocol';
import { expect, it } from 'vitest';
import { startTransport, probe, createUser, rpc } from '../helpers/wss.js';

it('keeps one real WSS connection through 60 seconds idle with production heartbeat timing', async () => {
  const app = await startTransport();
  try {
    const ws = app.connect();
    await once(ws, 'open');
    await createUser(ws);
    expect((await rpc(ws, T.LIST_FILES)).header.messageType).toBe(T.RESULT);
    const before = await probe(ws, 1);
    const started = Date.now();
    await delay(60500);
    const after = await probe(ws, 2);
    expect((await rpc(ws, T.LIST_FILES)).header.messageType).toBe(T.RESULT);
    expect(after.json?.['connectionId']).toBe(before.json?.['connectionId']);
    expect(app.events.filter((e) => e.event === 'ping').length).toBeGreaterThanOrEqual(3);
    expect(app.events.filter((e) => e.event === 'pong').length).toBeGreaterThanOrEqual(3);
    const directory = stageSevenEvidence();
    await mkdir(directory, { recursive: true });
    await writeFile(
      join(directory, 'keepalive.json'),
      JSON.stringify(
        {
          result: 'PASS',
          idleMs: Date.now() - started,
          heartbeatMs: 20000,
          defaultAuthenticationMs: 10000,
          authenticated: true,
          before: before.json,
          after: after.json,
          events: app.events,
        },
        null,
        2,
      ),
    );
  } finally {
    await app.stop();
  }
});
