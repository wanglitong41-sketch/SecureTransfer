import { once } from 'node:events';
import { stageSevenEvidence } from '../helpers/evidence.js';
import { performance } from 'node:perf_hooks';
import { setTimeout as sleep } from 'node:timers/promises';
import { writeFile } from 'node:fs/promises';
import { expect, it } from 'vitest';
import { MESSAGE_TYPES as T } from '@securetransfer/protocol';
import { createUser, probe, rpc, startTransport } from '../helpers/wss.js';

it(
  'keeps five distinct users online and serving requests for ten minutes',
  { timeout: 630000 },
  async () => {
    const app = await startTransport();
    try {
      const clients = [];
      for (let index = 0; index < 5; index++) {
        const ws = app.connect();
        await once(ws, 'open');
        const user = await createUser(ws, 'soak_' + index);
        const { json } = await probe(ws, 1);
        clients.push({ ws, userId: user['userId'], connectionId: json?.['connectionId'] });
      }
      expect(new Set(clients.map(({ userId }) => userId)).size).toBe(5);
      expect(new Set(clients.map(({ connectionId }) => connectionId)).size).toBe(5);
      expect(clients.every(({ connectionId }) => typeof connectionId === 'string')).toBe(true);
      const started = performance.now();
      const rounds: { elapsedMs: number; successfulRequests: number }[] = [];
      for (let index = 0; ; index++) {
        await Promise.all(
          clients.map(async ({ ws, connectionId }) => {
            const listing = await rpc(ws, T.LIST_FILES);
            expect(listing.header.messageType).toBe(T.RESULT);
            expect(listing.json?.['items']).toEqual([]);
            const result = await probe(ws, index + 2);
            expect(result.json?.['connectionId']).toBe(connectionId);
          }),
        );
        rounds.push({ elapsedMs: Math.round(performance.now() - started), successfulRequests: 10 });
        if (performance.now() - started >= 600000) break;
        const planned = started + (index + 1) * 30000;
        await sleep(Math.max(0, planned - performance.now()));
      }
      expect(rounds.length).toBeGreaterThanOrEqual(21);
      await writeFile(
        stageSevenEvidence('stability.json'),
        JSON.stringify(
          {
            result: 'PASS',
            users: clients.length,
            elapsedMs: rounds.at(-1)?.elapsedMs,
            requests: rounds.reduce((sum, round) => sum + round.successfulRequests, 0),
            rounds,
          },
          null,
          2,
        ),
      );
    } finally {
      await app.stop();
    }
  },
);
