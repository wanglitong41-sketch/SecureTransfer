import { createHash, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { openStore } from '../../apps/server/src/database/store.js';

export function seedFile(dataRoot: string, userId: string, name = 'example.txt') {
  const db = openStore(dataRoot);
  const fileId = randomUUID();
  const content = Buffer.from('stage-three test file');
  writeFileSync(join(dataRoot, 'storage', fileId), content);
  try {
    db.prepare('INSERT INTO files VALUES (?, ?, ?, ?, ?, ?)').run(
      fileId,
      userId,
      name,
      content.length,
      createHash('sha256').update(content).digest('hex'),
      new Date().toISOString(),
    );
  } finally {
    db.close();
  }
  return { fileId, name, size: content.length };
}
