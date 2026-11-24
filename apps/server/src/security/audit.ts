import { appendFileSync, existsSync, mkdirSync, renameSync, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

export interface AuditRecord {
  event: string;
  connectionId?: string;
  userId?: string;
  fileId?: string;
  transferId?: string;
  direction?: 'upload' | 'download';
  requestId?: number;
  messageType?: number;
  activeTransfers?: number;
  status?: number;
  code?: number;
  errorCode?: string;
}
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export class AuditLogger {
  private bytes: number;
  private closed = false;
  private readonly path: string;
  healthy = true;
  constructor(
    root: string,
    private readonly maxBytes = 10 * 1024 * 1024,
  ) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 512)
      throw new Error('Invalid audit rotation size');
    const directory = join(root, 'logs');
    mkdirSync(directory, { recursive: true });
    this.path = join(directory, 'audit.jsonl');
    appendFileSync(this.path, '', 'utf8');
    this.bytes = statSync(this.path).size;
  }
  write(event: AuditRecord) {
    if (this.closed || !this.healthy || !/^[a-z][a-z0-9_]{1,63}$/.test(event.event)) return;
    const record: Record<string, string | number> = {
      timestamp: new Date().toISOString(),
      event: event.event,
    };
    for (const key of ['connectionId', 'userId', 'fileId'] as const) {
      const value = event[key];
      if (value && UUID.test(value)) record[key] = value;
    }
    if (
      event.transferId &&
      /^[1-9][0-9]{0,19}$/.test(event.transferId) &&
      BigInt(event.transferId) <= 0xffffffffffffffffn
    )
      record['transferId'] = event.transferId;
    for (const key of ['requestId', 'messageType', 'activeTransfers', 'status', 'code'] as const) {
      const value = event[key];
      if (
        typeof value === 'number' &&
        Number.isSafeInteger(value) &&
        value >= 0 &&
        value <= 0xffffffff
      )
        record[key] = value;
    }
    if (event.direction === 'upload' || event.direction === 'download')
      record['direction'] = event.direction;
    if (event.errorCode && /^[A-Z][A-Z0-9_]{1,63}$/.test(event.errorCode))
      record['errorCode'] = event.errorCode;
    const line = JSON.stringify(record) + '\n';
    try {
      const count = Buffer.byteLength(line);
      if (this.bytes + count > this.maxBytes) {
        const oldest = this.path.replace('.jsonl', '.2.jsonl');
        const previous = this.path.replace('.jsonl', '.1.jsonl');
        if (existsSync(oldest)) unlinkSync(oldest);
        if (existsSync(previous)) renameSync(previous, oldest);
        if (existsSync(this.path)) renameSync(this.path, previous);
        this.bytes = 0;
      }
      appendFileSync(this.path, line, 'utf8');
      this.bytes += count;
    } catch {
      this.healthy = false;
      console.error('Audit log unavailable; protected requests will be refused.');
    }
  }
  close() {
    if (this.closed) return;
    this.write({ event: 'service_stopped' });
    this.closed = true;
  }
}
