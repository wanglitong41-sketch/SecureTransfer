import { randomBytes, randomUUID, createHash } from 'node:crypto';
import {
  openSync,
  closeSync,
  writeSync,
  readSync,
  statSync,
  fstatSync,
  unlinkSync,
  renameSync,
  existsSync,
  truncateSync,
  createReadStream,
} from 'node:fs';
import { requireRegularFile } from '../security/paths.js';
import { join } from 'node:path';
import {
  MESSAGE_TYPES as T,
  CHUNK_BYTES,
  MAX_FILE_BYTES,
  ProtocolError,
  encodeMessage,
} from '@securetransfer/protocol';
import type { ProtocolMessage, TransferDirection } from '@securetransfer/protocol';
import type { Store } from '../database/store.js';
import type { FileService } from '../files/service.js';
import { UNLIMITED_FLOW } from './flow-control.js';
import type { TransferFlowControl } from './flow-control.js';

export interface TransferContext {
  connectionId: string;
  userId: string;
  signal: AbortSignal;
  assertActive(): void;
  send(packet: Uint8Array): Promise<void>;
  event(
    event: string,
    transferId: string,
    direction: TransferDirection,
    activeTransfers: number,
  ): void;
}
export interface TransferOptions {
  flow: TransferFlowControl;
  ackMs: number;
  writeBlock: (fd: number, bytes: Uint8Array, offset: number) => void;
}
function writeFully(fd: number, bytes: Uint8Array, offset: number) {
  let written = 0;
  while (written < bytes.length) {
    const count = writeSync(fd, bytes, written, bytes.length - written, offset + written);
    if (count <= 0) throw new Error('Incomplete disk write');
    written += count;
  }
}
interface BaseTask {
  id: bigint;
  userId: string;
  connectionId: string;
  fileId: string;
  name: string;
  size: number;
  sha256: string;
  offset: number;
  fd: number | null;
  context: TransferContext;
  direction: TransferDirection;
  updatedAt: number;
  abort: AbortController;
}
interface UploadTask extends BaseTask {
  direction: 'upload';
  state: 'ACTIVE' | 'VERIFYING' | 'COMMITTING';
}
interface DownloadTask extends BaseTask {
  direction: 'download';
  state: 'ACTIVE' | 'VERIFYING';
  ready: boolean;
  pending: { packet: Uint8Array; expected: number; retries: number } | undefined;
  timer: ReturnType<typeof setTimeout> | undefined;
}
type Task = UploadTask | DownloadTask;
interface SavedUpload {
  id: string;
  user_id: string;
  file_id: string;
  name: string;
  size: number;
  sha256: string;
  confirmed_offset: number;
  state: string;
  reserved_bytes: number;
  updated_at: number;
}
export class TransferService {
  private tasks = new Map<bigint, Task>();
  private readonly options: TransferOptions;
  private readonly cleanupTimer: ReturnType<typeof setInterval>;
  constructor(
    private readonly db: Store,
    private readonly root: string,
    private readonly files: FileService,
    overrides: Partial<TransferOptions> = {},
  ) {
    this.options = { flow: UNLIMITED_FLOW, ackMs: 10000, writeBlock: writeFully, ...overrides };
    this.cleanupTimer = setInterval(() => this.cleanup(), 10 * 60 * 1000);
  }
  private temp(id: string) {
    if (!/^[1-9][0-9]{0,19}$/.test(id) || BigInt(id) > 0xffffffffffffffffn)
      throw new ProtocolError('Invalid saved transfer ID');
    return join(this.root, 'temp', id + '.part');
  }
  private allocateId() {
    let id: bigint;
    do {
      id = randomBytes(8).readBigUInt64BE();
    } while (
      id === 0n ||
      this.tasks.has(id) ||
      this.db.prepare('SELECT id FROM transfers WHERE id=?').get(id.toString())
    );
    return id;
  }
  private limits(userId: string) {
    if (
      this.tasks.size >= 12 ||
      [...this.tasks.values()].filter((task) => task.userId === userId).length >= 3
    ) {
      throw new ProtocolError('Transfer limit reached', 'RATE_LIMITED');
    }
  }
  private announce(task: Task, event: string) {
    task.context.event(event, task.id.toString(), task.direction, this.tasks.size);
  }
  private row(id: bigint) {
    return this.db.prepare('SELECT * FROM transfers WHERE id=?').get(id.toString()) as unknown as
      SavedUpload | undefined;
  }
  private task(context: TransferContext, id: bigint): Task {
    const task = this.tasks.get(id);
    if (!task || task.userId !== context.userId)
      throw new ProtocolError('Transfer not found', 'TRANSFER_NOT_FOUND');
    if (task.connectionId !== context.connectionId)
      throw new ProtocolError('Transfer belongs to another connection', 'TASK_BUSY');
    context.assertActive();
    return task;
  }
  private closeFd(task: Task) {
    if (task.fd !== null) {
      closeSync(task.fd);
      task.fd = null;
    }
  }
  private release(task: Task) {
    if (!this.tasks.has(task.id)) return;
    if (task.direction === 'download') clearTimeout(task.timer);
    task.abort.abort();
    this.closeFd(task);
    this.tasks.delete(task.id);
    this.announce(task, 'transfer_finished');
  }
  private markFailed(task: UploadTask, state = 'FAILED') {
    task.abort.abort();
    this.closeFd(task);
    this.db
      .prepare('UPDATE transfers SET state=?,updated_at=? WHERE id=?')
      .run(state, Date.now(), task.id.toString());
    this.clearTemporary(task.id.toString());
    this.tasks.delete(task.id);
    this.announce(task, state === 'CANCELLED' ? 'transfer_cancelled' : 'transfer_failed');
  }
  private clearTemporary(id: string) {
    try {
      const row = this.db.prepare('SELECT file_id,state FROM transfers WHERE id=?').get(id) as
        { file_id: string; state: string } | undefined;
      if (
        row &&
        row.state === 'FAILED' &&
        !this.db.prepare('SELECT id FROM files WHERE id=?').get(row.file_id)
      ) {
        const destination = this.files.pathFor(row.file_id);
        if (existsSync(destination)) unlinkSync(destination);
      }
      unlinkSync(this.temp(id));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return;
    }
    this.db.prepare('UPDATE transfers SET reserved_bytes=0 WHERE id=?').run(id);
  }
  async initialize() {
    const rows = this.db
      .prepare("SELECT * FROM transfers WHERE state NOT IN ('COMPLETED','FAILED','CANCELLED')")
      .all() as unknown as SavedUpload[];
    for (const row of rows) {
      if (row.state === 'COMMITTING') {
        await this.recoverCommit(row);
        continue;
      }
      if (row.state === 'INIT' || !existsSync(this.temp(row.id))) {
        this.db
          .prepare("UPDATE transfers SET state='FAILED',updated_at=? WHERE id=?")
          .run(Date.now(), row.id);
        this.clearTemporary(row.id);
        continue;
      }
      requireRegularFile(join(this.root, 'temp'), this.temp(row.id));
      const offset = Math.min(statSync(this.temp(row.id)).size, row.confirmed_offset, row.size);
      truncateSync(this.temp(row.id), offset);
      this.db
        .prepare("UPDATE transfers SET state='PAUSED',confirmed_offset=? WHERE id=?")
        .run(offset, row.id);
    }
    for (const row of this.db
      .prepare("SELECT * FROM transfers WHERE state='COMPLETED'")
      .all() as unknown as SavedUpload[]) {
      if (!existsSync(this.files.pathFor(row.file_id))) {
        this.db.prepare('DELETE FROM files WHERE id=?').run(row.file_id);
        this.db.prepare("UPDATE transfers SET state='FAILED' WHERE id=?").run(row.id);
      }
    }
    this.cleanup();
  }
  private async digest(path: string) {
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(path)) hash.update(chunk);
    return hash.digest('hex');
  }
  private publish(row: SavedUpload) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db
        .prepare('INSERT OR IGNORE INTO files VALUES (?, ?, ?, ?, ?, ?)')
        .run(row.file_id, row.user_id, row.name, row.size, row.sha256, new Date().toISOString());
      this.db
        .prepare("UPDATE transfers SET state='COMPLETED',reserved_bytes=0,updated_at=? WHERE id=?")
        .run(Date.now(), row.id);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  private async recoverCommit(row: SavedUpload) {
    const destination = this.files.pathFor(row.file_id);
    const path = existsSync(destination) ? destination : this.temp(row.id);
    if (
      existsSync(path) &&
      statSync(path).size === row.size &&
      (await this.digest(path)) === row.sha256
    ) {
      if (path !== destination) renameSync(path, destination);
      this.publish(row);
    } else {
      this.db
        .prepare("UPDATE transfers SET state='FAILED',updated_at=? WHERE id=?")
        .run(Date.now(), row.id);
      this.clearTemporary(row.id);
    }
  }
  cleanup() {
    for (const task of this.tasks.values()) {
      if (
        task.direction === 'upload' &&
        task.state === 'ACTIVE' &&
        Date.now() - task.updatedAt >= 5 * 60 * 1000
      ) {
        this.pause(task);
      }
    }
    const expired = this.db
      .prepare(
        "SELECT id FROM transfers WHERE (state='PAUSED' AND updated_at<?) OR state IN ('FAILED','CANCELLED')",
      )
      .all(Date.now() - 24 * 60 * 60 * 1000) as { id: string }[];
    for (const row of expired) {
      this.db
        .prepare("UPDATE transfers SET state='CANCELLED' WHERE id=? AND state='PAUSED'")
        .run(row.id);
      this.clearTemporary(row.id);
    }
    this.db
      .prepare(
        "DELETE FROM transfers WHERE reserved_bytes=0 AND state IN ('COMPLETED','FAILED','CANCELLED') AND updated_at<?",
      )
      .run(Date.now() - 24 * 60 * 60 * 1000);
  }
  private pause(task: UploadTask) {
    task.abort.abort();
    this.closeFd(task);
    this.db
      .prepare("UPDATE transfers SET state='PAUSED',updated_at=? WHERE id=?")
      .run(Date.now(), task.id.toString());
    this.tasks.delete(task.id);
    this.announce(task, 'transfer_paused');
  }

  listUploads(userId: string, after = '') {
    const rows = this.db
      .prepare(
        "SELECT * FROM transfers WHERE user_id=? AND id>? AND state IN ('PAUSED','ACTIVE','VERIFYING','COMMITTING','COMPLETED') AND updated_at>? ORDER BY id LIMIT 11",
      )
      .all(userId, after, Date.now() - 86400000) as unknown as SavedUpload[];
    return {
      items: rows.slice(0, 10).map((row) => ({
        transferId: row.id,
        name: row.name,
        size: row.size,
        sha256: row.sha256,
        confirmedOffset: row.confirmed_offset,
        state: row.state,
        updatedAt: new Date(row.updated_at).toISOString(),
        ...(row.state === 'COMPLETED' ? { fileId: row.file_id } : {}),
      })),
      nextAfter: rows.length > 10 ? rows[9]!.id : null,
    };
  }
  pauseUpload(context: TransferContext, id: bigint) {
    const row = this.row(id);
    if (!row || row.user_id !== context.userId)
      throw new ProtocolError('Transfer not found', 'TRANSFER_NOT_FOUND');
    if (row.state === 'PAUSED') return row.confirmed_offset;
    const task = this.task(context, id);
    if (task.direction !== 'upload' || task.state !== 'ACTIVE')
      throw new ProtocolError('Upload busy', 'TASK_BUSY');
    this.pause(task);
    return task.offset;
  }
  resumeUpload(context: TransferContext, id: bigint, size: number, sha256: string) {
    const row = this.row(id);
    if (
      !row ||
      row.user_id !== context.userId ||
      ['FAILED', 'CANCELLED'].includes(row.state) ||
      (row.state === 'PAUSED' && Date.now() - row.updated_at >= 86400000)
    ) {
      throw new ProtocolError('Transfer not found', 'TRANSFER_NOT_FOUND');
    }
    if (row.size !== size || row.sha256 !== sha256)
      throw new ProtocolError('Source file differs', 'HASH_MISMATCH');
    if (row.state === 'COMPLETED')
      return { state: 'COMPLETED', offset: row.size, fileId: row.file_id };
    if (row.state === 'ACTIVE') {
      const active = this.task(context, id);
      return { state: 'ACTIVE', offset: active.offset };
    }
    if (row.state !== 'PAUSED') throw new ProtocolError('Upload busy', 'TASK_BUSY');
    this.limits(context.userId);
    const path = this.temp(row.id);
    requireRegularFile(join(this.root, 'temp'), path);
    const fd = openSync(path, 'r+');
    let offset: number;
    const now = Date.now();
    try {
      offset = Math.min(fstatSync(fd).size, row.confirmed_offset, row.size);
      truncateSync(path, offset);
      this.db
        .prepare("UPDATE transfers SET state='ACTIVE',confirmed_offset=?,updated_at=? WHERE id=?")
        .run(offset, now, row.id);
    } catch (error) {
      closeSync(fd);
      throw error;
    }
    const task: UploadTask = {
      id,
      userId: context.userId,
      connectionId: context.connectionId,
      context,
      fileId: row.file_id,
      name: row.name,
      size,
      sha256,
      offset,
      fd,
      direction: 'upload',
      state: 'ACTIVE',
      updatedAt: now,
      abort: new AbortController(),
    };
    this.tasks.set(id, task);
    this.announce(task, 'transfer_resumed');
    return { state: 'ACTIVE', offset };
  }
  initUpload(context: TransferContext, name: string, size: number, sha256: string) {
    this.limits(context.userId);
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_BYTES)
      throw new ProtocolError('File too large', 'SIZE_LIMIT_EXCEEDED');
    const id = this.allocateId(),
      fileId = randomUUID(),
      now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const occupied = (userId?: string) =>
        Number(
          this.db
            .prepare(
              userId
                ? 'SELECT COALESCE(SUM(size),0) AS n FROM files WHERE user_id=?'
                : 'SELECT COALESCE(SUM(size),0) AS n FROM files',
            )
            .get(...(userId ? [userId] : []))!['n'],
        ) +
        Number(
          this.db
            .prepare(
              userId
                ? 'SELECT COALESCE(SUM(reserved_bytes),0) AS n FROM transfers WHERE user_id=?'
                : 'SELECT COALESCE(SUM(reserved_bytes),0) AS n FROM transfers',
            )
            .get(...(userId ? [userId] : []))!['n'],
        );
      if (
        occupied(context.userId) + size > 512 * 1024 * 1024 ||
        occupied() + size > 2 * 1024 * 1024 * 1024
      ) {
        throw new ProtocolError('Storage quota exceeded', 'QUOTA_EXCEEDED');
      }
      const count = Number(
        this.db
          .prepare(
            "SELECT COUNT(*) AS n FROM transfers WHERE user_id=? AND state NOT IN ('COMPLETED','FAILED','CANCELLED')",
          )
          .get(context.userId)!['n'],
      );
      if (count >= 20) throw new ProtocolError('Too many unfinished uploads', 'RATE_LIMITED');
      this.db
        .prepare("INSERT INTO transfers VALUES (?, ?, ?, ?, ?, ?, 0, 'INIT', ?, ?, ?)")
        .run(id.toString(), context.userId, fileId, name, size, sha256, size, now, now);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    let fd: number;
    try {
      fd = openSync(this.temp(id.toString()), 'wx');
    } catch (error) {
      this.db
        .prepare("UPDATE transfers SET state='FAILED',reserved_bytes=0 WHERE id=?")
        .run(id.toString());
      throw error;
    }
    const task: UploadTask = {
      id,
      userId: context.userId,
      connectionId: context.connectionId,
      context,
      fileId,
      name,
      size,
      sha256,
      fd,
      offset: 0,
      direction: 'upload',
      state: 'ACTIVE',
      updatedAt: now,
      abort: new AbortController(),
    };
    this.db.prepare("UPDATE transfers SET state='ACTIVE' WHERE id=?").run(id.toString());
    this.tasks.set(id, task);
    this.announce(task, 'transfer_started');
    return task;
  }
  async uploadChunk(context: TransferContext, message: ProtocolMessage) {
    const task = this.task(context, message.header.transferId);
    if (task.direction !== 'upload' || task.state !== 'ACTIVE')
      throw new ProtocolError('Upload not active', 'INVALID_STATE');
    const offset = Number(message.header.offset),
      end = offset + message.payload.length;
    const duplicate = end <= task.offset;
    if (!duplicate && (offset !== task.offset || end > task.size))
      throw new ProtocolError('Unexpected upload offset', 'INVALID_OFFSET', task.offset);
    await this.options.flow.waitForBytes(
      task.userId,
      'upload',
      message.payload.length,
      AbortSignal.any([context.signal, task.abort.signal]),
    );
    task.abort.signal.throwIfAborted();
    context.assertActive();
    if (duplicate) return task.offset;
    try {
      this.options.writeBlock(task.fd!, message.payload, offset);
      this.db
        .prepare('UPDATE transfers SET confirmed_offset=?,updated_at=? WHERE id=?')
        .run(end, Date.now(), task.id.toString());
      task.offset = end;
      task.updatedAt = Date.now();
      return end;
    } catch (error) {
      this.markFailed(task);
      throw error;
    }
  }
  async finishUpload(context: TransferContext, id: bigint, offset: number) {
    const saved = this.row(id);
    if (!saved || saved.user_id !== context.userId)
      throw new ProtocolError('Transfer not found', 'TRANSFER_NOT_FOUND');
    if (offset !== saved.size)
      throw new ProtocolError('Invalid finish offset', 'INVALID_OFFSET', saved.size);
    if (['VERIFYING', 'COMMITTING'].includes(saved.state))
      throw new ProtocolError('Upload is being committed', 'TASK_BUSY');
    if (saved.state === 'COMPLETED') return { fileId: saved.file_id, size: saved.size };
    const task = this.task(context, id);
    if (
      task.direction !== 'upload' ||
      task.state !== 'ACTIVE' ||
      task.offset !== task.size ||
      offset !== task.size
    ) {
      throw new ProtocolError('Upload incomplete', 'INVALID_OFFSET', task.offset);
    }
    task.state = 'VERIFYING';
    this.closeFd(task);
    this.db.prepare("UPDATE transfers SET state='VERIFYING' WHERE id=?").run(id.toString());
    let valid: boolean;
    try {
      valid =
        statSync(this.temp(id.toString())).size === task.size &&
        (await this.digest(this.temp(id.toString()))) === task.sha256;
    } catch (error) {
      this.markFailed(task);
      throw error;
    }
    if (!valid) {
      this.markFailed(task);
      throw new ProtocolError('File integrity mismatch', 'HASH_MISMATCH');
    }
    task.state = 'COMMITTING';
    this.db.prepare("UPDATE transfers SET state='COMMITTING' WHERE id=?").run(id.toString());
    try {
      renameSync(this.temp(id.toString()), this.files.pathFor(task.fileId));
      this.publish(this.row(id)!);
    } finally {
      this.tasks.delete(id);
      this.announce(task, 'transfer_finished');
    }
    return { fileId: task.fileId, size: task.size };
  }
  initDownload(context: TransferContext, fileId: string) {
    this.limits(context.userId);
    const file = this.files.get(context.userId, fileId);
    const fd = openSync(this.files.pathFor(fileId), 'r');
    if (fstatSync(fd).size !== file.size) {
      closeSync(fd);
      throw new ProtocolError('Stored file size mismatch', 'HASH_MISMATCH');
    }
    const id = this.allocateId();
    const task: DownloadTask = {
      ...file,
      id,
      userId: context.userId,
      connectionId: context.connectionId,
      context,
      offset: 0,
      fd,
      direction: 'download',
      state: 'ACTIVE',
      ready: false,
      pending: undefined,
      timer: undefined,
      updatedAt: Date.now(),
      abort: new AbortController(),
    };
    this.tasks.set(id, task);
    this.announce(task, 'transfer_started');
    task.timer = setTimeout(
      () => this.failDownload(task, 'Download did not start'),
      this.options.ackMs,
    );
    return task;
  }
  private failDownload(task: DownloadTask, reason: string) {
    if (!this.tasks.has(task.id)) return;
    void task.context
      .send(encodeMessage(T.ERROR, 0, { code: 'INVALID_STATE', message: reason }, task.id))
      .catch(() => {});
    this.announce(task, 'transfer_timeout');
    this.release(task);
  }
  private armDownload(task: DownloadTask) {
    clearTimeout(task.timer);
    task.timer = setTimeout(
      () => {
        if (!this.tasks.has(task.id)) return;
        if (!task.pending || task.pending.retries >= 3) {
          this.failDownload(task, 'Acknowledgement timeout');
          return;
        }
        const pending = task.pending;
        pending.retries++;
        void (async () => {
          await this.options.flow.waitForBytes(
            task.userId,
            'download',
            pending.packet.length - 32,
            AbortSignal.any([task.context.signal, task.abort.signal]),
          );
          task.context.assertActive();
          if (!this.tasks.has(task.id) || task.pending !== pending) return;
          await task.context.send(pending.packet);
          if (task.pending === pending) this.armDownload(task);
        })().catch(() => {
          if (this.tasks.has(task.id)) this.release(task);
        });
      },
      task.state === 'VERIFYING' ? 120000 : this.options.ackMs,
    );
  }
  async acknowledge(context: TransferContext, id: bigint, offset: number) {
    const task = this.task(context, id);
    if (task.direction === 'download' && task.state === 'VERIFYING' && offset === task.size) return;
    if (task.direction !== 'download' || task.state !== 'ACTIVE')
      throw new ProtocolError('Download not active', 'INVALID_STATE');
    if (!task.ready) {
      if (offset !== 0)
        throw new ProtocolError('Expected ready acknowledgement', 'INVALID_OFFSET', 0);
      task.ready = true;
    } else {
      if (offset === task.offset) return;
      if (!task.pending || offset !== task.pending.expected)
        throw new ProtocolError(
          'Unexpected download acknowledgement',
          'INVALID_OFFSET',
          task.pending?.expected ?? task.offset,
        );
      task.offset = offset;
      task.pending = undefined;
    }
    clearTimeout(task.timer);
    if (task.offset === task.size) {
      task.state = 'VERIFYING';
      await context.send(encodeMessage(T.TRANSFER_FINISH, 0, {}, task.id, BigInt(task.size)));
      this.armDownload(task);
      return;
    }
    const count = Math.min(CHUNK_BYTES, task.size - task.offset);
    await this.options.flow.waitForBytes(task.userId, 'download', count, context.signal);
    context.assertActive();
    const buffer = Buffer.allocUnsafe(count);
    let received = 0;
    try {
      while (received < count) {
        const read = readSync(task.fd!, buffer, received, count - received, task.offset + received);
        if (!read) throw new Error('Stored file ended early');
        received += read;
      }
      const packet = encodeMessage(T.FILE_CHUNK, 0, buffer, task.id, BigInt(task.offset));
      task.pending = { packet, expected: task.offset + count, retries: 0 };
      await context.send(packet);
      this.armDownload(task);
    } catch (error) {
      this.release(task);
      throw error;
    }
  }
  completeDownload(context: TransferContext, message: ProtocolMessage) {
    const task = this.task(context, message.header.transferId);
    if (
      task.direction !== 'download' ||
      task.state !== 'VERIFYING' ||
      Number(message.header.offset) !== task.size
    ) {
      throw new ProtocolError('Unexpected download result', 'INVALID_STATE');
    }
    if (message.header.messageType === T.RESULT && message.json?.['fileId'] !== task.fileId)
      throw new ProtocolError('Download result mismatch');
    this.announce(
      task,
      message.header.messageType === T.RESULT ? 'download_verified' : 'transfer_failed',
    );
    this.release(task);
  }
  cancel(context: TransferContext, id: bigint) {
    const row = this.row(id),
      task = this.tasks.get(id);
    if (task) {
      this.task(context, id);
      if (task.direction === 'upload') {
        if (task.state !== 'ACTIVE')
          throw new ProtocolError('Upload is being committed', 'TASK_BUSY');
        this.markFailed(task, 'CANCELLED');
      } else this.release(task);
      return task.offset;
    }
    if (!row || row.user_id !== context.userId)
      throw new ProtocolError('Transfer not found', 'TRANSFER_NOT_FOUND');
    if (!['PAUSED', 'FAILED', 'CANCELLED'].includes(row.state))
      throw new ProtocolError('Transfer cannot be cancelled', 'TASK_BUSY');
    this.db
      .prepare("UPDATE transfers SET state='CANCELLED',updated_at=? WHERE id=?")
      .run(Date.now(), id.toString());
    this.clearTemporary(id.toString());
    return row.confirmed_offset;
  }
  disconnect(connectionId: string) {
    for (const task of [...this.tasks.values()]) {
      if (task.connectionId !== connectionId) continue;
      if (task.direction === 'download') this.release(task);
      else if (task.state === 'ACTIVE') this.pause(task);
    }
  }
  isDownloading(fileId: string) {
    return [...this.tasks.values()].some(
      (task) => task.direction === 'download' && task.fileId === fileId,
    );
  }
  shutdown() {
    clearInterval(this.cleanupTimer);
    for (const task of [...this.tasks.values()]) this.disconnect(task.connectionId);
  }
}
