import { createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { ProtocolError } from '@securetransfer/protocol';
import type { PublicKeyChallenge, PublicKeyProof } from '@securetransfer/protocol';
import type { Store } from '../database/store.js';

interface Pending {
  challenge: PublicKeyChallenge;
  userId: string;
  publicKey: string;
  purpose: 'login' | 'enroll';
  label: string;
}
function reject(): never {
  throw new ProtocolError('Public key proof rejected', 'UNAUTHORIZED');
}
function parseKey(value: string): KeyObject {
  try {
    const key = createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
    if (
      key.asymmetricKeyType === 'ec' &&
      key.asymmetricKeyDetails?.namedCurve === 'prime256v1' &&
      key.export({ format: 'der', type: 'spki' }).toString('base64') === value
    )
      return key;
  } catch {
    /* Treat invalid encodings consistently. */
  }
  return reject();
}
export class PublicKeys {
  private pending = new Map<string, Pending>();
  constructor(
    private readonly db: Store,
    private readonly now: () => number,
  ) {}
  clear(connection: string) {
    this.pending.delete(connection);
  }
  login(connection: string, origin: string, username: string, keyId: string) {
    const row = this.db
      .prepare(
        'SELECT k.user_id AS userId,k.public_key_spki AS publicKey FROM user_keys k JOIN users u ON u.id=k.user_id WHERE k.id=? AND u.username=? AND revoked_at IS NULL',
      )
      .get(keyId, username.toLowerCase()) as { userId: string; publicKey: string } | undefined;
    if (!row) return reject();
    return this.challenge(
      connection,
      origin,
      username.toLowerCase(),
      keyId,
      row.userId,
      row.publicKey,
      'login',
      '',
    );
  }
  enroll(
    connection: string,
    origin: string,
    username: string,
    userId: string,
    publicKey: string,
    label: string,
  ) {
    parseKey(publicKey);
    const count = this.db
      .prepare('SELECT COUNT(*) AS n FROM user_keys WHERE user_id=? AND revoked_at IS NULL')
      .get(userId);
    if (Number(count?.['n']) >= 10) throw new ProtocolError('Key limit reached', 'RATE_LIMITED');
    return this.challenge(
      connection,
      origin,
      username,
      randomUUID(),
      userId,
      publicKey,
      'enroll',
      label,
    );
  }
  private challenge(
    connection: string,
    origin: string,
    username: string,
    keyId: string,
    userId: string,
    publicKey: string,
    purpose: Pending['purpose'],
    label: string,
  ) {
    const challengeId = randomUUID();
    const nonceBase64 = randomBytes(32).toString('base64');
    const signingDataBase64 = Buffer.from(
      JSON.stringify([
        'SecureTransfer:key-' + purpose + ':v1',
        origin,
        username,
        keyId,
        challengeId,
        nonceBase64,
      ]),
    ).toString('base64');
    const challenge = {
      challengeId,
      keyId,
      username,
      origin,
      nonceBase64,
      signingDataBase64,
      expiresAt: new Date(this.now() + 60000).toISOString(),
    };
    this.pending.set(connection, { challenge, userId, publicKey, purpose, label });
    return challenge;
  }
  verifyProof(
    connection: string,
    origin: string,
    proof: PublicKeyProof,
    purpose: Pending['purpose'],
    userId?: string,
  ) {
    const pending = this.pending.get(connection);
    this.clear(connection);
    if (
      !pending ||
      pending.purpose !== purpose ||
      pending.challenge.origin !== origin ||
      Date.parse(pending.challenge.expiresAt) <= this.now() ||
      pending.challenge.challengeId !== proof.challengeId ||
      pending.challenge.keyId !== proof.keyId ||
      (userId !== undefined && pending.userId !== userId)
    )
      return reject();
    if (
      purpose === 'login' &&
      !this.db
        .prepare('SELECT 1 FROM user_keys WHERE id=? AND user_id=? AND revoked_at IS NULL')
        .get(proof.keyId, pending.userId)
    )
      return reject();
    const signature = Buffer.from(proof.signatureBase64, 'base64');
    if (
      signature.length !== 64 ||
      signature.toString('base64') !== proof.signatureBase64 ||
      !verify(
        'sha256',
        Buffer.from(pending.challenge.signingDataBase64, 'base64'),
        { key: parseKey(pending.publicKey), dsaEncoding: 'ieee-p1363' },
        signature,
      )
    )
      return reject();
    return pending;
  }
  save(pending: Pending) {
    const createdAt = this.now();
    const keyId = pending.challenge.keyId;
    const record = this.db.prepare('INSERT INTO user_keys VALUES (?, ?, ?, ?, ?, NULL)');
    const count = this.db
      .prepare('SELECT COUNT(*) AS n FROM user_keys WHERE user_id=? AND revoked_at IS NULL')
      .get(pending.userId);
    if (Number(count?.['n']) >= 10) throw new ProtocolError('Key limit reached', 'RATE_LIMITED');
    record.run(keyId, pending.userId, pending.publicKey, pending.label, createdAt);
    return { keyId, label: pending.label, createdAt: new Date(createdAt).toISOString() };
  }
  list(userId: string) {
    return this.db
      .prepare(
        'SELECT id AS keyId,label,created_at AS createdAt FROM user_keys WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at',
      )
      .all(userId)
      .map((row) => ({
        keyId: String(row['keyId']),
        label: String(row['label']),
        createdAt: new Date(Number(row['createdAt'])).toISOString(),
      }));
  }
  remove(userId: string, keyId: string) {
    if (
      !this.db
        .prepare(
          'UPDATE user_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL',
        )
        .run(this.now(), keyId, userId).changes
    ) {
      throw new ProtocolError('Key not found', 'FORBIDDEN');
    }
    this.db.prepare('DELETE FROM sessions WHERE user_id=?').run(userId);
  }
}
