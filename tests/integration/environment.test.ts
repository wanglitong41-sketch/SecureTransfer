import { DatabaseSync } from 'node:sqlite';
import { hash, verify, argon2id } from 'argon2';
import { describe, expect, it } from 'vitest';

describe('Windows runtime dependencies', () => {
  it('binds SQLite values without interpreting SQL input', () => {
    const database = new DatabaseSync(':memory:');
    try {
      database.exec('CREATE TABLE samples (value TEXT NOT NULL)');
      const input = "name'); DROP TABLE samples; --";
      database.prepare('INSERT INTO samples(value) VALUES (?)').run(input);
      expect(database.prepare('SELECT value FROM samples').get()).toEqual({ value: input });
    } finally {
      database.close();
    }
  });

  it('runs Argon2id and rejects an incorrect password', async () => {
    const passwordHash = await hash('stage-one-fixture', {
      type: argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });
    expect(passwordHash.startsWith('$argon2id$')).toBe(true);
    expect(await verify(passwordHash, 'stage-one-fixture')).toBe(true);
    expect(await verify(passwordHash, 'incorrect-fixture')).toBe(false);
  });
});
