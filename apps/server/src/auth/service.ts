import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { hash, verify, argon2id } from 'argon2';
import { ProtocolError } from '@securetransfer/protocol';
import type { Store } from '../database/store.js';

export interface Identity {
  userId: string;
  username: string;
  sessionHash: string;
  expiresAt: number;
}
export interface AuthOptions {
  now: () => number;
  idleMs: number;
  lifetimeMs: number;
  passwordConcurrency: number;
  loginIpPerMinute: number;
  loginUserPerMinute: number;
  registerPerMinute: number;
}
export const DEFAULT_AUTH_OPTIONS: AuthOptions = {
  now: Date.now,
  idleMs: 30 * 60 * 1000,
  lifetimeMs: 8 * 60 * 60 * 1000,
  passwordConcurrency: 2,
  loginIpPerMinute: 30,
  loginUserPerMinute: 10,
  registerPerMinute: 10,
};
interface SessionRow {
  userId: string;
  username: string;
  expiresAt: number;
  lastActivityAt: number;
}
export class AuthService {
  readonly options: AuthOptions;
  private passwordJobs = 0;
  private windows = new Map<string, { start: number; count: number }>();
  constructor(
    private readonly db: Store,
    overrides: Partial<AuthOptions> = {},
  ) {
    this.options = { ...DEFAULT_AUTH_OPTIONS, ...overrides };
    // Never retain expired database sessions indefinitely across service starts.
    this.cleanupExpired();
  }
  cleanupExpired() {
    this.db
      .prepare('DELETE FROM sessions WHERE expires_at <= ? OR last_activity_at <= ?')
      .run(this.options.now(), this.options.now() - this.options.idleMs);
  }
  private consume(key: string, limit: number) {
    const now = this.options.now();
    for (const [name, value] of this.windows)
      if (now - value.start >= 60000) this.windows.delete(name);
    const window = this.windows.get(key) ?? { start: now, count: 0 };
    this.windows.set(key, window);
    if (++window.count > limit)
      throw new ProtocolError('Too many authentication attempts', 'RATE_LIMITED');
  }
  private async passwordJob<T>(work: () => Promise<T>) {
    if (this.passwordJobs >= this.options.passwordConcurrency)
      throw new ProtocolError('Authentication busy', 'RATE_LIMITED');
    this.passwordJobs++;
    try {
      return await work();
    } finally {
      this.passwordJobs--;
    }
  }
  async register(username: string, password: string) {
    const name = username.toLowerCase();
    this.consume('register', this.options.registerPerMinute);
    if (this.db.prepare('SELECT id FROM users WHERE username = ?').get(name)) {
      throw new ProtocolError('Username already exists', 'USERNAME_TAKEN');
    }
    const passwordHash = await this.passwordJob(() =>
      hash(password, {
        type: argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      }),
    );
    const userId = randomUUID();
    try {
      this.db
        .prepare('INSERT INTO users(id, username, password_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(userId, name, passwordHash, this.options.now());
    } catch (error) {
      if (this.db.prepare('SELECT id FROM users WHERE username = ?').get(name)) {
        throw new ProtocolError('Username already exists', 'USERNAME_TAKEN');
      }
      throw error;
    }
    return { userId, username: name };
  }
  limitLogin(username: string, ip: string) {
    this.consume('ip:' + ip, this.options.loginIpPerMinute);
    this.consume('user:' + username.toLowerCase(), this.options.loginUserPerMinute);
  }
  async verifyPassword(username: string, password: string, ip: string) {
    const name = username.toLowerCase();
    this.limitLogin(name, ip);
    const row = this.db
      .prepare('SELECT id, password_hash FROM users WHERE username = ?')
      .get(name) as { id: string; password_hash: string } | undefined;
    if (!row || !(await this.passwordJob(() => verify(row.password_hash, password)))) {
      throw new ProtocolError('Invalid username or password', 'UNAUTHORIZED');
    }
    return row.id;
  }
  async login(username: string, password: string, ip: string) {
    return this.issueSession(await this.verifyPassword(username, password, ip));
  }
  /** Server-side identity proof adapters (password and public key) share this session path. */
  issueSession(userId: string) {
    const user = this.db.prepare('SELECT username FROM users WHERE id=?').get(userId) as
      { username: string } | undefined;
    if (!user) throw new ProtocolError('User not found', 'UNAUTHORIZED');
    const token = randomBytes(32).toString('hex');
    const sessionHash = this.hashToken(token);
    const now = this.options.now();
    const expiresAt = now + this.options.lifetimeMs;
    this.db
      .prepare('INSERT INTO sessions VALUES (?, ?, ?, ?, ?)')
      .run(sessionHash, userId, now, now, expiresAt);
    return { userId, username: user.username, token, expiresAt: new Date(expiresAt).toISOString() };
  }
  hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }
  resume(token: string) {
    return this.check(this.hashToken(token), true);
  }
  check(sessionHash: string, touch = false): Identity {
    const row = this.db
      .prepare(
        `
      SELECT s.user_id AS userId, u.username, s.expires_at AS expiresAt, s.last_activity_at AS lastActivityAt
      FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash = ?
    `,
      )
      .get(sessionHash) as SessionRow | undefined;
    const now = this.options.now();
    if (!row || row.expiresAt <= now || row.lastActivityAt + this.options.idleMs <= now) {
      this.revoke(sessionHash);
      throw new ProtocolError('Session expired or invalid', 'UNAUTHORIZED');
    }
    if (touch)
      this.db
        .prepare('UPDATE sessions SET last_activity_at=? WHERE token_hash=?')
        .run(now, sessionHash);
    return { userId: row.userId, username: row.username, sessionHash, expiresAt: row.expiresAt };
  }
  revoke(sessionHash: string) {
    this.db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sessionHash);
  }
}
