import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { existsSync, readdirSync, writeSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { describe, it, expect, afterAll } from 'vitest';
import { MESSAGE_TYPES as T, MAX_FILE_BYTES } from '@securetransfer/protocol';
import { startTransport, createUser, rpc, probe } from '../helpers/wss.js';
import {
  WireInbox,
  uploadBytes,
  downloadBytes,
  beginUpload,
  wireSend,
  sha256,
} from '../helpers/transfers.js';
import { openStore } from '../../apps/server/src/database/store.js';
import { AuthService } from '../../apps/server/src/auth/service.js';
import { createApp } from '../../apps/server/src/app.js';
import { testRuntime } from '../helpers/runtime.js';

const roundTrips: {
  size: number;
  expectedSha256: string;
  actualSha256: string;
  elapsedMs: number;
}[] = [];
afterAll(() =>
  writeFileSync('docs/evidence/stage-7/round-trips.json', JSON.stringify(roundTrips, null, 2)),
);

describe('stage-four file transfer', () => {
  it.each([0, 1, 65535, 65536, 65537, 1024 * 1024, 10 * 1024 * 1024, MAX_FILE_BYTES])(
    'round-trips %s bytes with matching SHA-256',
    async (size) => {
      const app = await startTransport();
      try {
        const ws = app.connect();
        await once(ws, 'open');
        await createUser(ws);
        const content = Buffer.alloc(size, 0x5a);
        const started = performance.now();
        const created = await uploadBytes(ws, content, '中文_' + size + '.bin');
        const received = await downloadBytes(ws, created.fileId);
        roundTrips.push({
          size,
          expectedSha256: sha256(content),
          actualSha256: sha256(received),
          elapsedMs: performance.now() - started,
        });
        expect(received.length).toBe(size);
        expect(sha256(received)).toBe(sha256(content));
        const repeated = await rpc(ws, T.TRANSFER_FINISH, {}, created.transferId, BigInt(size));
        expect(repeated.json?.['fileId']).toBe(created.fileId);
        expect((await rpc(ws, T.LIST_FILES)).json?.['items']).toHaveLength(1);
        expect((await probe(ws, 1)).json?.['stage']).toBe(6);
      } finally {
        await app.stop();
      }
    },
    90000,
  );
  it('deduplicates a repeated block and rejects jumps/overlaps without corrupting the upload', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      await createUser(ws);
      const content = Buffer.from('abcdefgh');
      const id = await beginUpload(ws, content),
        inbox = new WireInbox(ws, id);
      try {
        await wireSend(ws, T.FILE_CHUNK, content.subarray(0, 4), id);
        expect(Number((await inbox.next()).header.offset)).toBe(4);
        await wireSend(ws, T.FILE_CHUNK, content.subarray(0, 4), id);
        expect(Number((await inbox.next()).header.offset)).toBe(4);
        await wireSend(ws, T.FILE_CHUNK, content.subarray(2, 6), id, 2);
        const error = await inbox.next();
        expect(error.json).toMatchObject({ code: 'INVALID_OFFSET', expectedOffset: 4 });
        await wireSend(ws, T.FILE_CHUNK, content.subarray(4), id, 4);
        expect(Number((await inbox.next()).header.offset)).toBe(8);
        const done = await rpc(ws, T.TRANSFER_FINISH, {}, id, 8n);
        expect(await downloadBytes(ws, String(done.json?.['fileId']))).toEqual(content);
      } finally {
        inbox.dispose();
      }
    } finally {
      await app.stop();
    }
  });
  it('does not publish hash failures and frees their temporary storage reservation', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      await createUser(ws);
      await expect(
        uploadBytes(ws, Buffer.from('bad hash fixture'), 'bad.bin', '0'.repeat(64)),
      ).rejects.toThrow('HASH_MISMATCH');
      expect((await rpc(ws, T.LIST_FILES)).json?.['items']).toHaveLength(0);
      expect(readdirSync(join(app.dataRoot, 'temp'))).toHaveLength(0);
      const db = openStore(app.dataRoot);
      try {
        expect(
          Number(db.prepare('SELECT SUM(reserved_bytes) AS n FROM transfers').get()!['n']),
        ).toBe(0);
      } finally {
        db.close();
      }
      expect((await uploadBytes(ws, Buffer.from('good'))).fileId).toBeTruthy();
    } finally {
      await app.stop();
    }
  });
  it('refuses another user’s download and transfer ID', async () => {
    const app = await startTransport();
    try {
      const a = app.connect();
      await once(a, 'open');
      const alice = await createUser(a, 'alice');
      const file = await uploadBytes(a, Buffer.from('private'));
      const id = await beginUpload(a, Buffer.from('pending'));
      const b = app.connect();
      await once(b, 'open');
      await createUser(b, 'bob');
      expect((await rpc(b, T.DOWNLOAD_INIT, { fileId: file.fileId })).json?.['code']).toBe(
        'FILE_NOT_FOUND',
      );
      const inbox = new WireInbox(b, id);
      try {
        await wireSend(b, T.FILE_CHUNK, Buffer.from('x'), id);
        expect((await inbox.next()).json?.['code']).toBe('TRANSFER_NOT_FOUND');
      } finally {
        inbox.dispose();
      }
      expect((await rpc(b, T.CANCEL_TRANSFER, {}, id)).json?.['code']).toBe('TRANSFER_NOT_FOUND');
      expect((await rpc(a, T.CANCEL_TRANSFER, {}, id)).header.messageType).toBe(T.RESULT);
      expect(alice['userId']).toBeTruthy();
    } finally {
      await app.stop();
    }
  });
  it('locks a downloaded file until cancellation releases its file handle', async () => {
    const app = await startTransport();
    try {
      const ws = app.connect();
      await once(ws, 'open');
      await createUser(ws);
      const file = await uploadBytes(ws, Buffer.alloc(65537));
      const started = await rpc(ws, T.DOWNLOAD_INIT, { fileId: file.fileId });
      expect((await rpc(ws, T.DELETE_FILE, { fileId: file.fileId })).json?.['code']).toBe(
        'TASK_BUSY',
      );
      await rpc(ws, T.CANCEL_TRANSFER, {}, started.header.transferId);
      expect((await rpc(ws, T.DELETE_FILE, { fileId: file.fileId })).header.messageType).toBe(
        T.RESULT,
      );
      expect(existsSync(join(app.dataRoot, 'storage', file.fileId))).toBe(false);
    } finally {
      await app.stop();
    }
  });
  it('retransmits only the unconfirmed download block and releases a timed-out task', async () => {
    const app = await startTransport({}, {}, { ackMs: 40 });
    try {
      const ws = app.connect();
      await once(ws, 'open');
      await createUser(ws);
      const file = await uploadBytes(ws, Buffer.from('retry fixture'));
      const started = await rpc(ws, T.DOWNLOAD_INIT, { fileId: file.fileId });
      const inbox = new WireInbox(ws, started.header.transferId);
      try {
        await wireSend(ws, T.CHUNK_ACK, new Uint8Array(), started.header.transferId);
        const packets = [];
        for (let n = 0; n < 4; n++) packets.push(await inbox.next());
        expect(
          packets.every(
            (packet) => packet.header.messageType === T.FILE_CHUNK && packet.header.offset === 0n,
          ),
        ).toBe(true);
        expect((await inbox.next()).header.messageType).toBe(T.ERROR);
        expect((await rpc(ws, T.DELETE_FILE, { fileId: file.fileId })).header.messageType).toBe(
          T.RESULT,
        );
      } finally {
        inbox.dispose();
      }
    } finally {
      await app.stop();
    }
  });
  it('cleans a partial disk write without confirming or publishing it', async () => {
    const app = await startTransport(
      {},
      {},
      {
        writeBlock(fd, bytes, offset) {
          writeSync(fd, bytes, 0, 1, offset);
          throw new Error('Injected write failure');
        },
      },
    );
    try {
      const ws = app.connect();
      await once(ws, 'open');
      await createUser(ws);
      const id = await beginUpload(ws, Buffer.from('partial write')),
        inbox = new WireInbox(ws, id);
      const closed = once(ws, 'close');
      try {
        await wireSend(ws, T.FILE_CHUNK, Buffer.from('partial write'), id);
        expect((await inbox.next()).json?.['code']).toBe('INTERNAL_ERROR');
        expect((await closed)[0]).toBe(1002);
        expect(readdirSync(join(app.dataRoot, 'temp'))).toHaveLength(0);
        expect(readdirSync(join(app.dataRoot, 'storage'))).toHaveLength(0);
      } finally {
        inbox.dispose();
      }
    } finally {
      await app.stop();
    }
  });
  it('reserves quota across disconnected partial uploads and frees it through cancellation', async () => {
    const app = await startTransport();
    try {
      let ws = app.connect();
      await once(ws, 'open');
      const session = await createUser(ws);
      const ids: bigint[] = [];
      for (let n = 0; n < 3; n++) {
        const result = await rpc(ws, T.UPLOAD_INIT, {
          name: 'quota.bin',
          size: MAX_FILE_BYTES,
          sha256: '0'.repeat(64),
        });
        ids.push(result.header.transferId);
      }
      ws.close();
      await once(ws, 'close');
      await delay(10);
      ws = app.connect();
      await once(ws, 'open');
      await rpc(ws, T.AUTH_RESUME, { token: session['token'] });
      for (let n = 0; n < 2; n++) {
        const result = await rpc(ws, T.UPLOAD_INIT, {
          name: 'quota.bin',
          size: MAX_FILE_BYTES,
          sha256: '0'.repeat(64),
        });
        ids.push(result.header.transferId);
      }
      expect(
        (
          await rpc(ws, T.UPLOAD_INIT, {
            name: 'quota.bin',
            size: MAX_FILE_BYTES,
            sha256: '0'.repeat(64),
          })
        ).json?.['code'],
      ).toBe('QUOTA_EXCEEDED');
      for (const id of ids) await rpc(ws, T.CANCEL_TRANSFER, {}, id);
      expect((await uploadBytes(ws, Buffer.from('quota released'))).fileId).toBeTruthy();
    } finally {
      await app.stop();
    }
  });
  it('calls the future bandwidth interface with server-owned identity for both directions', async () => {
    const calls: { userId: string; direction: string; bytes: number }[] = [];
    const app = await startTransport(
      {},
      {},
      {
        flow: {
          async waitForBytes(userId, direction, bytes, signal) {
            signal.throwIfAborted();
            calls.push({ userId, direction, bytes });
          },
        },
      },
    );
    try {
      const ws = app.connect();
      await once(ws, 'open');
      const user = await createUser(ws);
      const content = Buffer.alloc(65537);
      const file = await uploadBytes(ws, content);
      await downloadBytes(ws, file.fileId);
      expect(calls.every((call) => call.userId === user['userId'])).toBe(true);
      for (const direction of ['upload', 'download'])
        expect(
          calls
            .filter((call) => call.direction === direction)
            .reduce((sum, call) => sum + call.bytes, 0),
        ).toBe(content.length);
    } finally {
      await app.stop();
    }
  });
  it('serves six simultaneous mixed transfers for six authenticated users', async () => {
    const app = await startTransport();
    try {
      const clients = [];
      for (let n = 0; n < 6; n++) {
        const ws = app.connect();
        await once(ws, 'open');
        await createUser(ws, 'parallel_' + n);
        clients.push(ws);
      }
      const bytes = Buffer.alloc(1024 * 1024, 0xa5);
      const existing: { fileId: string; transferId: bigint }[] = [];
      for (let n = 3; n < 6; n++) existing.push(await uploadBytes(clients[n]!, bytes));
      const results = await Promise.all([
        ...clients.slice(0, 3).map((ws) => uploadBytes(ws, bytes)),
        ...clients.slice(3).map((ws, n) => downloadBytes(ws, existing[n]!.fileId)),
      ]);
      for (const value of results.slice(3)) expect(sha256(value as Buffer)).toBe(sha256(bytes));
      expect(
        Math.max(...app.events.map((event) => event.activeTransfers ?? 0)),
      ).toBeGreaterThanOrEqual(6);
    } finally {
      await app.stop();
    }
  }, 20000);
  it.each([false, true])('recovers a persisted COMMITTING upload (renamed=%s)', async (renamed) => {
    const runtime = testRuntime();
    const bytes = Buffer.from('recover committed upload');
    const id = '12345',
      fileId = randomUUID(),
      db = openStore(runtime.config.dataRoot);
    const user = await new AuthService(db).register('recover_user', 'fixture-recovery');
    db.prepare("INSERT INTO transfers VALUES (?, ?, ?, ?, ?, ?, ?, 'COMMITTING', ?, ?, ?)").run(
      id,
      user.userId,
      fileId,
      'recovered.bin',
      bytes.length,
      sha256(bytes),
      bytes.length,
      bytes.length,
      Date.now(),
      Date.now(),
    );
    writeFileSync(join(runtime.config.dataRoot, 'temp', id + '.part'), bytes);
    if (renamed)
      renameSync(
        join(runtime.config.dataRoot, 'temp', id + '.part'),
        join(runtime.config.dataRoot, 'storage', fileId),
      );
    db.close();
    const server = await createApp(runtime.config, { onEvent: () => {} });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const reopened = openStore(runtime.config.dataRoot);
      try {
        expect(
          reopened.prepare('SELECT state,reserved_bytes FROM transfers WHERE id=?').get(id),
        ).toEqual({ state: 'COMPLETED', reserved_bytes: 0 });
        expect(reopened.prepare('SELECT id FROM files WHERE user_id=?').all(user.userId)).toEqual([
          { id: fileId },
        ]);
      } finally {
        reopened.close();
      }
    } finally {
      server.shutdownWebSockets();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await server.resourcesClosed;
      runtime.cleanup();
    }
  });
});

it('rejects an oversized declaration and reserved Windows names without allocating a file', async () => {
  const app = await startTransport();
  try {
    const ws = app.connect();
    await once(ws, 'open');
    await createUser(ws);
    expect(
      (
        await rpc(ws, T.UPLOAD_INIT, {
          name: 'large.bin',
          size: MAX_FILE_BYTES + 1,
          sha256: '0'.repeat(64),
        })
      ).json?.['code'],
    ).toBe('SIZE_LIMIT_EXCEEDED');
    expect(readdirSync(join(app.dataRoot, 'temp'))).toHaveLength(0);
    expect((await rpc(ws, T.LIST_FILES)).json?.['items']).toHaveLength(0);
    const closed = once(ws, 'close');
    expect(
      (await rpc(ws, T.UPLOAD_INIT, { name: 'CON.txt', size: 0, sha256: sha256(Buffer.alloc(0)) }))
        .json?.['code'],
    ).toBe('INVALID_MESSAGE');
    await closed;
  } finally {
    await app.stop();
  }
});

it('rejects corrupted download bytes rather than confirming their integrity', async () => {
  const app = await startTransport();
  try {
    const ws = app.connect();
    await once(ws, 'open');
    await createUser(ws);
    const file = await uploadBytes(ws, Buffer.from('original'));
    writeFileSync(join(app.dataRoot, 'storage', file.fileId), Buffer.from('tampered'));
    await expect(downloadBytes(ws, file.fileId)).rejects.toThrow('HASH_MISMATCH');
    expect((await rpc(ws, T.DELETE_FILE, { fileId: file.fileId })).header.messageType).toBe(
      T.RESULT,
    );
  } finally {
    await app.stop();
  }
});

it('performs ten real file operations without replacing the authenticated connection', async () => {
  const app = await startTransport();
  try {
    const ws = app.connect();
    await once(ws, 'open');
    await createUser(ws);
    const before = await probe(ws, 1);
    for (let n = 0; n < 5; n++) {
      await delay(200);
      const content = Buffer.from('sequential-' + n);
      const file = await uploadBytes(ws, content, 'sequential.txt');
      expect(await downloadBytes(ws, file.fileId)).toEqual(content);
    }
    expect((await probe(ws, 2)).json?.['connectionId']).toBe(before.json?.['connectionId']);
    expect(app.events.filter((event) => event.event === 'connected')).toHaveLength(1);
  } finally {
    await app.stop();
  }
});
