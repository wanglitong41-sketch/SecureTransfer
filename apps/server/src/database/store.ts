import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

export function openStore(dataRoot: string) {
  for (const name of ['database', 'storage', 'temp', 'logs'])
    mkdirSync(join(dataRoot, name), { recursive: true });
  const db = new DatabaseSync(join(dataRoot, 'database/securetransfer.db'));
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 3000;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS user_keys (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
      public_key_spki TEXT NOT NULL, label TEXT NOT NULL,
      created_at INTEGER NOT NULL, revoked_at INTEGER
    ) STRICT;
    CREATE INDEX IF NOT EXISTS user_keys_owner ON user_keys(user_id, revoked_at);
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
      created_at INTEGER NOT NULL, last_activity_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
      name TEXT NOT NULL, size INTEGER NOT NULL CHECK(size >= 0 AND size <= 104857600),
      sha256 TEXT NOT NULL, created_at TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS transfers (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
      file_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
      size INTEGER NOT NULL CHECK(size >= 0 AND size <= 104857600),
      sha256 TEXT NOT NULL, confirmed_offset INTEGER NOT NULL DEFAULT 0,
      state TEXT NOT NULL, reserved_bytes INTEGER NOT NULL,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS transfers_owner ON transfers(user_id, state);
    CREATE INDEX IF NOT EXISTS files_owner ON files(user_id, id);
  `);
  return db;
}
export type Store = ReturnType<typeof openStore>;
