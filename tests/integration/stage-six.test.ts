import { once } from 'node:events';
import { stageSevenEvidence } from '../helpers/evidence.js';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { CHUNK_BYTES, MESSAGE_TYPES as T } from '@securetransfer/protocol';
import { UserBandwidth, UNLIMITED_FLOW } from '../../apps/server/src/transfer/flow-control.js';
import { testRuntime } from '../helpers/runtime.js';
import { openStore } from '../../apps/server/src/database/store.js';
import { startTransport, rpc, createUser } from '../helpers/wss.js';
import {
  beginUpload,
  downloadBytes,
  uploadBytes,
  WireInbox,
  wireSend,
  sha256,
} from '../helpers/transfers.js';

function fixtureKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    proof(challenge: Record<string, unknown>) {
      return {
        challengeId: challenge['challengeId'],
        keyId: challenge['keyId'],
        signatureBase64: sign(
          'sha256',
          Buffer.from(String(challenge['signingDataBase64']), 'base64'),
          { key: privateKey, dsaEncoding: 'ieee-p1363' },
        ).toString('base64'),
      };
    },
  };
}

it('registers a signing key, binds proofs to the connection, expires challenges and revokes sessions', async () => {
  let time = Date.now();
  const app = await startTransport({}, { now: () => time });
  const open = async () => {
    const ws = app.connect();
    await once(ws, 'open');
    return ws;
  };
  try {
    const owner = await open();
    const session = await createUser(owner, 'key_owner');
    const key = fixtureKey();
    const enroll = (
      await rpc(owner, T.KEY_CHALLENGE, { publicKeySpki: key.spki, label: 'test browser' })
    ).json!;
    const enrolled = await rpc(owner, T.KEY_ENROLL, {
      ...key.proof(enroll),
      password: 'fixture-stage-three',
    });
    expect(enrolled.header.messageType).toBe(T.RESULT);
    const keyId = enrolled.json!['keyId'];
    expect((await rpc(owner, T.KEY_LIST)).json?.['items']).toEqual([enrolled.json]);
    const stranger = await open();
    const strangerSession = await createUser(stranger, 'independent_user');
    expect(
      (await rpc(stranger, T.KEY_REMOVE, { keyId, password: 'fixture-stage-three' })).json?.[
        'code'
      ],
    ).toBe('FORBIDDEN');

    const candidate = await open();
    const request = { username: 'key_owner', keyId };
    const challenge = (await rpc(candidate, T.KEY_CHALLENGE, request)).json!;
    const proof = key.proof(challenge);
    const other = await open();
    expect((await rpc(other, T.KEY_LOGIN, proof)).json?.['code']).toBe('UNAUTHORIZED');
    expect((await rpc(candidate, T.KEY_LOGIN, proof)).json?.['userId']).toBe(session['userId']);
    const replay = await open();
    expect((await rpc(replay, T.KEY_LOGIN, proof)).json?.['code']).toBe('UNAUTHORIZED');
    const wrong = await open();
    const wrongChallenge = (await rpc(wrong, T.KEY_CHALLENGE, request)).json!;
    expect((await rpc(wrong, T.KEY_LOGIN, fixtureKey().proof(wrongChallenge))).json?.['code']).toBe(
      'UNAUTHORIZED',
    );
    const expired = await open();
    const expiredChallenge = (await rpc(expired, T.KEY_CHALLENGE, request)).json!;
    time += 61000;
    expect((await rpc(expired, T.KEY_LOGIN, key.proof(expiredChallenge))).json?.['code']).toBe(
      'UNAUTHORIZED',
    );

    const ended = once(candidate, 'close');
    expect(
      (await rpc(owner, T.KEY_REMOVE, { keyId, password: 'fixture-stage-three' })).header
        .messageType,
    ).toBe(T.RESULT);
    await ended;
    const after = await open();
    expect((await rpc(after, T.KEY_CHALLENGE, request)).json?.['code']).toBe('UNAUTHORIZED');
    expect((await rpc(stranger, T.LIST_FILES)).header.messageType).toBe(T.RESULT);
    expect(strangerSession['userId']).not.toBe(session['userId']);
  } finally {
    await app.stop();
  }
});

it('resumes from the durable offset after pause and disconnect on a new authenticated connection', async () => {
  const app = await startTransport();
  const content = Buffer.concat([
    Buffer.alloc(CHUNK_BYTES, 2),
    Buffer.alloc(CHUNK_BYTES, 4),
    Buffer.from('finish'),
  ]);
  const packet = { size: content.length, sha256: sha256(content) };
  try {
    const first = app.connect();
    await once(first, 'open');
    const session = await createUser(first, 'resumer');
    const id = await beginUpload(first, content, 'resume.bin');
    const inbox = new WireInbox(first, id);
    await wireSend(first, T.FILE_CHUNK, content.subarray(0, CHUNK_BYTES), id);
    expect((await inbox.next()).header.offset).toBe(BigInt(CHUNK_BYTES));
    expect((await rpc(first, T.PAUSE_UPLOAD, {}, id)).header.offset).toBe(BigInt(CHUNK_BYTES));
    expect(
      (await rpc(first, T.RESUME_UPLOAD, { ...packet, sha256: '0'.repeat(64) }, id)).json?.['code'],
    ).toBe('HASH_MISMATCH');
    expect((await rpc(first, T.RESUME_UPLOAD, packet, id)).header.offset).toBe(BigInt(CHUNK_BYTES));
    await wireSend(
      first,
      T.FILE_CHUNK,
      content.subarray(CHUNK_BYTES, CHUNK_BYTES * 2),
      id,
      CHUNK_BYTES,
    );
    expect((await inbox.next()).header.offset).toBe(BigInt(2 * CHUNK_BYTES));
    inbox.dispose();
    const disconnect = once(first, 'close');
    first.close();
    await disconnect;
    writeFileSync(join(app.dataRoot, 'temp', id.toString() + '.part'), content, { flag: 'a' });

    const second = app.connect();
    await once(second, 'open');
    await rpc(second, T.AUTH_RESUME, { token: session['token'] });
    const list = await rpc(second, T.LIST_UPLOADS);
    expect(list.json?.['items']).toMatchObject([
      { state: 'PAUSED', confirmedOffset: CHUNK_BYTES * 2 },
    ]);
    expect((await rpc(second, T.RESUME_UPLOAD, packet, id)).header.offset).toBe(
      BigInt(2 * CHUNK_BYTES),
    );
    const remaining = new WireInbox(second, id);
    await wireSend(second, T.FILE_CHUNK, content.subarray(2 * CHUNK_BYTES), id, 2 * CHUNK_BYTES);
    expect((await remaining.next()).header.offset).toBe(BigInt(content.length));
    remaining.dispose();
    const finish = await rpc(second, T.TRANSFER_FINISH, {}, id, BigInt(content.length));
    expect(await downloadBytes(second, String(finish.json?.['fileId']))).toEqual(content);
    const completed = await rpc(second, T.RESUME_UPLOAD, packet, id);
    expect(completed.json).toMatchObject({ state: 'COMPLETED', fileId: finish.json?.['fileId'] });
  } finally {
    await app.stop();
  }
});

it(
  'enforces per-user upload and download rates across WSS connections',
  { timeout: 40000 },
  async () => {
    const vipUserIds: string[] = [];
    const policy = { ordinary: 256 * 1024, vip: 1024 * 1024, vipUserIds };
    let flow = UNLIMITED_FLOW;
    const app = await startTransport(
      {},
      {},
      { flow: { waitForBytes: (...args) => flow.waitForBytes(...args) } },
    );
    const size = 2 * 1024 * 1024;
    const bytes = Buffer.alloc(size, 5);
    const checksum = createHash('sha256').update(bytes).digest('hex');
    const samples: {
      tier: string;
      direction: string;
      bytes: number;
      elapsedMs: number;
      sha256: string;
      connections: number;
    }[] = [];
    async function measure(
      tier: string,
      direction: string,
      connections: number,
      work: () => Promise<void>,
    ) {
      const start = performance.now();
      await work();
      const sample = {
        tier,
        direction,
        bytes: size * connections,
        elapsedMs: performance.now() - start,
        sha256: checksum,
        connections,
      };
      samples.push(sample);
      return sample;
    }
    try {
      const ordinary = app.connect();
      await once(ordinary, 'open');
      const regularSession = await createUser(ordinary, 'regular');
      const vip = app.connect();
      await once(vip, 'open');
      vipUserIds.push(String((await createUser(vip, 'vip_user'))['userId']));
      await measure('unlimited', 'upload', 1, async () => {
        await uploadBytes(ordinary, bytes, 'baseline.bin');
      });
      flow = new UserBandwidth(policy);
      let ordinaryFile = '',
        vipFile = '';
      await Promise.all([
        measure('ordinary', 'upload', 1, async () => {
          ordinaryFile = (await uploadBytes(ordinary, bytes, 'regular.bin')).fileId;
        }),
        measure('vip', 'upload', 1, async () => {
          vipFile = (await uploadBytes(vip, bytes, 'vip.bin')).fileId;
        }),
      ]);
      const ordinarySecond = app.connect();
      await once(ordinarySecond, 'open');
      expect(
        (await rpc(ordinarySecond, T.AUTH_RESUME, { token: regularSession['token'] })).header
          .messageType,
      ).toBe(T.RESULT);
      await Promise.all([
        measure('ordinary', 'download', 2, async () => {
          const results = await Promise.all([
            downloadBytes(ordinary, ordinaryFile),
            downloadBytes(ordinarySecond, ordinaryFile),
          ]);
          for (const result of results) expect(sha256(result)).toBe(checksum);
        }),
        measure('vip', 'download', 1, async () => {
          expect(sha256(await downloadBytes(vip, vipFile))).toBe(checksum);
        }),
      ]);
      for (const sample of samples.filter(({ tier }) => tier !== 'unlimited')) {
        const expected = sample.tier === 'vip' ? policy.vip : policy.ordinary;
        const rate = sample.bytes / (sample.elapsedMs / 1000);
        expect(rate).toBeLessThan(expected * 1.2);
        expect(rate).toBeGreaterThan(expected * 0.8);
      }
    } finally {
      writeFileSync(
        stageSevenEvidence('bandwidth.json'),
        JSON.stringify({ policy, samples }, null, 2),
      );
      await app.stop();
    }
  },
);

it('cancels a bandwidth wait without spending the pending block', async () => {
  const limiter = new UserBandwidth({
    ordinary: CHUNK_BYTES,
    vip: 4 * CHUNK_BYTES,
    vipUserIds: [],
  });
  await limiter.waitForBytes('user', 'upload', CHUNK_BYTES, new AbortController().signal);
  const controller = new AbortController();
  const waiting = limiter.waitForBytes('user', 'upload', CHUNK_BYTES, controller.signal);
  controller.abort();
  await expect(waiting).rejects.toMatchObject({ name: 'AbortError' });
  await limiter.waitForBytes('user', 'download', CHUNK_BYTES, new AbortController().signal);
});

it('recovers an interrupted upload on service restart using persisted data', async () => {
  const runtime = testRuntime();
  let app = await startTransport({}, {}, {}, runtime);
  let stopped = false;
  try {
    const socket = app.connect();
    await once(socket, 'open');
    const session = await createUser(socket, 'restart_owner');
    const content = Buffer.alloc(CHUNK_BYTES + 21, 107);
    const id = await beginUpload(socket, content, 'restart.bin');
    const first = new WireInbox(socket, id);
    await wireSend(socket, T.FILE_CHUNK, content.subarray(0, CHUNK_BYTES), id);
    expect((await first.next()).header.offset).toBe(BigInt(CHUNK_BYTES));
    first.dispose();

    await app.stop(false);
    stopped = true;
    // Reproduce a process exit between persisting bytes and recording their confirmed offset.
    const db = openStore(runtime.config.dataRoot);
    try {
      db.prepare("UPDATE transfers SET state='ACTIVE' WHERE id=?").run(id.toString());
    } finally {
      db.close();
    }
    writeFileSync(
      join(app.dataRoot, 'temp', id.toString() + '.part'),
      content.subarray(CHUNK_BYTES),
      { flag: 'a' },
    );
    app = await startTransport({}, {}, {}, runtime);
    stopped = false;

    const resumed = app.connect();
    await once(resumed, 'open');
    expect(
      (await rpc(resumed, T.AUTH_RESUME, { token: session['token'] })).header.messageType,
    ).toBe(T.RESULT);
    expect(
      (await rpc(resumed, T.RESUME_UPLOAD, { size: content.length, sha256: sha256(content) }, id))
        .header.offset,
    ).toBe(BigInt(CHUNK_BYTES));
    const last = new WireInbox(resumed, id);
    await wireSend(resumed, T.FILE_CHUNK, content.subarray(CHUNK_BYTES), id, CHUNK_BYTES);
    expect((await last.next()).header.offset).toBe(BigInt(content.length));
    last.dispose();
    const finish = await rpc(resumed, T.TRANSFER_FINISH, {}, id, BigInt(content.length));
    expect(await downloadBytes(resumed, String(finish.json?.['fileId']))).toEqual(content);
  } finally {
    if (!stopped) await app.stop();
    else runtime.cleanup();
  }
});
