import { requireRegularFile } from '../security/paths.js';
import { unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { ProtocolError } from '@securetransfer/protocol';
import type { FileRecord } from '@securetransfer/protocol';
import type { Store } from '../database/store.js';

export class FileService {
  constructor(
    private readonly db: Store,
    private readonly dataRoot: string,
    private readonly busy: (fileId: string) => boolean = () => false,
  ) {
    const records = db.prepare('SELECT id FROM files').all() as { id: string }[];
    for (const row of records) {
      if (!existsSync(this.pathFor(row.id))) db.prepare('DELETE FROM files WHERE id=?').run(row.id);
    }
  }
  pathFor(fileId: string) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(fileId))
      throw new ProtocolError('Invalid file identity');
    return join(this.dataRoot, 'storage', fileId);
  }
  list(userId: string, after = '') {
    const rows = this.db
      .prepare(
        `
      SELECT id AS fileId, name, size, sha256, created_at AS createdAt
      FROM files WHERE user_id=? AND id>? ORDER BY id LIMIT 11
    `,
      )
      .all(userId, after) as unknown as FileRecord[];
    const items = rows.slice(0, 10);
    return { items, nextAfter: rows.length > 10 ? items.at(-1)!.fileId : null };
  }
  get(userId: string, fileId: string): FileRecord {
    const row = this.db
      .prepare(
        'SELECT id AS fileId, name, size, sha256, created_at AS createdAt FROM files WHERE id=? AND user_id=?',
      )
      .get(fileId, userId) as unknown as FileRecord | undefined;
    if (!row) throw new ProtocolError('File not found', 'FILE_NOT_FOUND');
    requireRegularFile(join(this.dataRoot, 'storage'), this.pathFor(fileId));
    return row;
  }
  delete(userId: string, fileId: string) {
    const row = this.db
      .prepare('SELECT id FROM files WHERE id=? AND user_id=?')
      .get(fileId, userId);
    if (!row) throw new ProtocolError('File not found', 'FILE_NOT_FOUND');
    if (this.busy(fileId)) throw new ProtocolError('File is being downloaded', 'TASK_BUSY');
    try {
      requireRegularFile(join(this.dataRoot, 'storage'), this.pathFor(fileId));
      unlinkSync(this.pathFor(fileId));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    this.db.prepare('DELETE FROM files WHERE id=? AND user_id=?').run(fileId, userId);
    return {};
  }
}
