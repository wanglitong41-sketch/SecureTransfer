import { spawn } from 'node:child_process';
import { PROJECT_ROOT } from '../../apps/server/src/config.js';
import { once } from 'node:events';
import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MESSAGE_TYPES as T, encodeMessage } from '@securetransfer/protocol';
import { openStore } from '../../apps/server/src/database/store.js';
import { AuthService } from '../../apps/server/src/auth/service.js';
import { FileService } from '../../apps/server/src/files/service.js';
import { testRuntime } from '../helpers/runtime.js';
import { startTransport, rpc, createUser } from '../helpers/wss.js';
import { seedFile } from '../helpers/files.js';

describe('registration, sessions and user ownership', () => {
  it('registers normalized names, rejects duplicates, and keeps credentials hashed', async () => {
    const runtime = testRuntime();
    let db = openStore(runtime.config.dataRoot);
    try {
      const auth = new AuthService(db);
      const user = await auth.register('ALIce', 'fixture-stage-three');
      expect(user.username).toBe('alice');
      await expect(auth.register('alice', 'fixture-stage-three')).rejects.toMatchObject({
        code: 'USERNAME_TAKEN',
      });
      const session = await auth.login('ALICE', 'fixture-stage-three', 'test');
      const hash = db.prepare('SELECT password_hash FROM users').get()!['password_hash'];
      expect(String(hash)).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
      expect(hash).not.toBe('fixture-stage-three');
      expect(db.prepare('SELECT token_hash FROM sessions').get()!['token_hash']).toBe(
        auth.hashToken(session.token),
      );
      expect(auth.resume(session.token).userId).toBe(user.userId);
      db.close();
      db = openStore(runtime.config.dataRoot);
      const restarted = new AuthService(db);
      expect(restarted.resume(session.token).userId).toBe(user.userId);
      expect((await restarted.login('alice', 'fixture-stage-three', 'test')).username).toBe(
        'alice',
      );
    } finally {
      db.close();
      runtime.cleanup();
    }
  });
  it('enforces idle and absolute expiry without heartbeat renewal', async () => {
    const runtime = testRuntime();
    const db = openStore(runtime.config.dataRoot);
    let now = 1000000;
    try {
      const auth = new AuthService(db, { now: () => now, idleMs: 100, lifetimeMs: 250 });
      await auth.register('alice', 'fixture-stage-three');
      const first = await auth.login('alice', 'fixture-stage-three', 'test');
      const id = auth.resume(first.token);
      now += 90;
      auth.check(id.sessionHash); // Heartbeats/checks do not touch idle activity.
      now += 11;
      expect(() => auth.resume(first.token)).toThrow();
      const second = await auth.login('alice', 'fixture-stage-three', 'test');
      for (let n = 0; n < 3; n++) {
        now += 80;
        auth.check(auth.hashToken(second.token), true);
      }
      now += 11;
      expect(() => auth.resume(second.token)).toThrow();
    } finally {
      db.close();
      runtime.cleanup();
    }
  });
  it('limits login attempts before password verification and bounds password work', async () => {
    const runtime = testRuntime();
    const db = openStore(runtime.config.dataRoot);
    try {
      const auth = new AuthService(db, { loginUserPerMinute: 1, passwordConcurrency: 1 });
      const first = auth.register('alice', 'fixture-stage-three');
      await expect(auth.register('bravo', 'fixture-stage-three')).rejects.toMatchObject({
        code: 'RATE_LIMITED',
      });
      await first;
      await expect(auth.login('alice', 'incorrect-fixture', 'test')).rejects.toMatchObject({
        code: 'UNAUTHORIZED',
      });
      await expect(auth.login('alice', 'fixture-stage-three', 'test')).rejects.toMatchObject({
        code: 'RATE_LIMITED',
      });
    } finally {
      db.close();
      runtime.cleanup();
    }
  });
  it('returns only owned paginated files, handles bound SQL-like names, and deletes only owned entities', async () => {
    const app = await startTransport();
    try {
      const a = app.connect();
      await once(a, 'open');
      const alice = await createUser(a, 'alice');
      const b = app.connect();
      await once(b, 'open');
      const bob = await createUser(b, 'bob');
      const own = [];
      for (let n = 0; n < 12; n++)
        own.push(
          seedFile(
            app.dataRoot,
            String(alice['userId']),
            n === 0 ? "x'); DROP TABLE files;--.txt" : 'file-' + n,
          ),
        );
      const foreign = seedFile(app.dataRoot, String(bob['userId']), 'private.txt');
      const page = await rpc(a, T.LIST_FILES);
      expect(page.json?.['items']).toHaveLength(10);
      const next = await rpc(a, T.LIST_FILES, { after: page.json!['nextAfter'] });
      expect(next.json?.['items']).toHaveLength(2);
      expect(next.json?.['nextAfter']).toBeNull();
      const rows = [
        ...(page.json!['items'] as { fileId: string }[]),
        ...(next.json!['items'] as { fileId: string }[]),
      ];
      expect(new Set(rows.map((row) => row.fileId))).toEqual(
        new Set(own.map((file) => file.fileId)),
      );
      expect((await rpc(a, T.DELETE_FILE, { fileId: foreign.fileId })).json?.['code']).toBe(
        'FILE_NOT_FOUND',
      );
      expect(existsSync(join(app.dataRoot, 'storage', foreign.fileId))).toBe(true);
      expect((await rpc(a, T.DELETE_FILE, { fileId: own[0]!.fileId })).header.messageType).toBe(
        T.RESULT,
      );
      expect(existsSync(join(app.dataRoot, 'storage', own[0]!.fileId))).toBe(false);
      expect((await rpc(a, T.DELETE_FILE, { fileId: own[0]!.fileId })).json?.['code']).toBe(
        'FILE_NOT_FOUND',
      );
    } finally {
      await app.stop();
    }
  });
  it('resumes a real session, revokes all its connections on logout, and rejects token replay', async () => {
    const app = await startTransport();
    try {
      const a = app.connect();
      await once(a, 'open');
      const session = await createUser(a);
      const b = app.connect();
      await once(b, 'open');
      expect((await rpc(b, T.AUTH_RESUME, { token: session['token'] })).header.messageType).toBe(
        T.RESULT,
      );
      expect((await rpc(b, T.LIST_FILES)).header.messageType).toBe(T.RESULT);
      const closedA = once(a, 'close'),
        closedB = once(b, 'close');
      expect((await rpc(a, T.LOGOUT)).header.messageType).toBe(T.RESULT);
      expect((await closedA)[0]).toBe(1000);
      expect((await closedB)[0]).toBe(1000);
      const c = app.connect();
      await once(c, 'open');
      const closedC = once(c, 'close');
      expect((await rpc(c, T.AUTH_RESUME, { token: session['token'] })).json?.['code']).toBe(
        'UNAUTHORIZED',
      );
      expect((await closedC)[0]).toBe(1008);
    } finally {
      await app.stop();
    }
  });
  it('rejects malformed injection/path inputs without changing accounts or files', async () => {
    const app = await startTransport();
    try {
      const a = app.connect();
      await once(a, 'open');
      const user = await createUser(a);
      const file = seedFile(app.dataRoot, String(user['userId']));
      const closed = once(a, 'close');
      expect((await rpc(a, T.DELETE_FILE, { fileId: '../../outside' })).json?.['code']).toBe(
        'INVALID_MESSAGE',
      );
      await closed;
      expect(readFileSync(join(app.dataRoot, 'storage', file.fileId), 'utf8')).toContain(
        'test file',
      );
      const b = app.connect();
      await once(b, 'open');
      const closedB = once(b, 'close');
      expect(
        (await rpc(b, T.LOGIN, { username: "alice' OR 1=1--", password: 'fixture-stage-three' }))
          .json?.['code'],
      ).toBe('INVALID_MESSAGE');
      await closedB;
      const c = app.connect();
      await once(c, 'open');
      expect(
        (await rpc(c, T.LOGIN, { username: 'alice', password: 'fixture-stage-three' })).header
          .messageType,
      ).toBe(T.RESULT);
    } finally {
      await app.stop();
    }
  });
  it('cleans metadata for missing entities on startup', async () => {
    const runtime = testRuntime();
    const db = openStore(runtime.config.dataRoot);
    try {
      const auth = new AuthService(db);
      const user = await auth.register('alice', 'fixture-stage-three');
      db.prepare('INSERT INTO files VALUES (?, ?, ?, ?, ?, ?)').run(
        '00000000-0000-4000-8000-000000000001',
        user.userId,
        'lost.txt',
        0,
        '0'.repeat(64),
        new Date().toISOString(),
      );
      const files = new FileService(db, runtime.config.dataRoot);
      expect(files.list(user.userId).items).toHaveLength(0);
    } finally {
      db.close();
      runtime.cleanup();
    }
  });
  it('closes expired sessions using the sweep', async () => {
    let now = 1000000;
    const app = await startTransport({ sessionSweepMs: 30 }, { now: () => now, idleMs: 100 });
    try {
      const ws = app.connect();
      await once(ws, 'open');
      await createUser(ws);
      const closed = once(ws, 'close');
      now += 101;
      expect((await closed)[0]).toBe(1008);
    } finally {
      await app.stop();
    }
  });
});

it('keeps five different authenticated users online with independent file lists', async () => {
  const app = await startTransport();
  try {
    const clients = [];
    const identities = [];
    for (let n = 0; n < 5; n++) {
      const ws = app.connect();
      await once(ws, 'open');
      identities.push(await createUser(ws, 'user_' + n));
      clients.push(ws);
    }
    for (let n = 0; n < clients.length; n++)
      seedFile(app.dataRoot, String(identities[n]!['userId']), 'private-' + n);
    const lists = await Promise.all(clients.map((ws) => rpc(ws, T.LIST_FILES)));
    for (let n = 0; n < lists.length; n++) {
      expect(lists[n]!.json?.['items']).toMatchObject([{ name: 'private-' + n }]);
    }
    const forged = await rpc(clients[0]!, T.LIST_FILES, { userId: identities[1]!['userId'] });
    expect(forged.json?.['items']).toMatchObject([{ name: 'private-0' }]);
    expect(app.events.filter((event) => event.event === 'authenticated')).toHaveLength(5);
  } finally {
    await app.stop();
  }
});

it('allows three connections per user and rejects a fourth without revoking the original session', async () => {
  const app = await startTransport();
  try {
    const first = app.connect();
    await once(first, 'open');
    const session = await createUser(first);
    for (let n = 0; n < 2; n++) {
      const next = app.connect();
      await once(next, 'open');
      expect((await rpc(next, T.AUTH_RESUME, { token: session['token'] })).header.messageType).toBe(
        T.RESULT,
      );
    }
    const fourth = app.connect();
    await once(fourth, 'open');
    expect((await rpc(fourth, T.AUTH_RESUME, { token: session['token'] })).json?.['code']).toBe(
      'RATE_LIMITED',
    );
    expect((await rpc(first, T.LIST_FILES)).header.messageType).toBe(T.RESULT);
  } finally {
    await app.stop();
  }
});

it('rejects a reused in-flight request ID while registration is asynchronous', async () => {
  const app = await startTransport();
  try {
    const ws = app.connect();
    await once(ws, 'open');
    const closed = once(ws, 'close');
    ws.send(
      encodeMessage(T.REGISTER, 900, { username: 'duplicate_id', password: 'fixture-stage-three' }),
    );
    ws.send(encodeMessage(T.PROBE, 900, { sequence: 1 }));
    expect((await closed)[0]).toBe(1002);
  } finally {
    await app.stop();
  }
});

it('exits on an occupied startup port instead of retaining the session sweep timer', async () => {
  const app = await startTransport();
  const runtime = testRuntime();
  try {
    const address = app.server.address() as import('node:net').AddressInfo;
    const child = spawn(process.execPath, [join(PROJECT_ROOT, 'apps/server/dist/index.js')], {
      cwd: PROJECT_ROOT,
      env: { ...process.env, ST_PORT: String(address.port), ST_DATA_DIR: runtime.config.dataRoot },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => child.kill(), 5000);
    try {
      const [code] = await once(child, 'exit');
      expect(code).toBe(1);
      expect(stderr).toContain('EADDRINUSE');
    } finally {
      clearTimeout(timer);
    }
  } finally {
    await app.stop();
    runtime.cleanup();
  }
});
