import { MESSAGE_TYPES as T, CHUNK_BYTES, MAX_FILE_BYTES } from '@securetransfer/protocol';
import type { ProtocolMessage, TransferProgress, FileRecord } from '@securetransfer/protocol';
import type { ConnectionManager } from './connection';
import { digest } from './hash';

class Inbox {
  private queue: ProtocolMessage[] = [];
  private waiter:
    | {
        resolve: (packet: ProtocolMessage) => void;
        reject: (error: Error) => void;
        timer: ReturnType<typeof setTimeout>;
      }
    | undefined;
  private error: Error | undefined;
  readonly detach: () => void;
  constructor(
    manager: ConnectionManager,
    id: bigint,
    private readonly signal: AbortSignal,
  ) {
    this.detach = manager.attachTransfer(
      id,
      (packet) => {
        if (this.waiter) {
          const waiter = this.waiter;
          this.waiter = undefined;
          clearTimeout(waiter.timer);
          waiter.resolve(packet);
        } else if (this.queue.length < 3) this.queue.push(packet);
        else this.close(new Error('Transfer queue exceeded'));
      },
      (error) => this.close(error),
    );
    signal.addEventListener('abort', this.abort, { once: true });
  }
  private abort = () => this.close(new DOMException('Cancelled', 'AbortError'));
  close(error: Error) {
    this.error = error;
    if (this.waiter) {
      clearTimeout(this.waiter.timer);
      this.waiter.reject(error);
      this.waiter = undefined;
    }
  }
  dispose() {
    this.detach();
    this.signal.removeEventListener('abort', this.abort);
    this.queue.length = 0;
  }
  async next(timeout = 10000): Promise<ProtocolMessage> {
    this.signal.throwIfAborted();
    if (this.error) throw this.error;
    const packet =
      this.queue.shift() ??
      (await new Promise<ProtocolMessage>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.waiter = undefined;
          reject(new Error('Acknowledgement timeout'));
        }, timeout);
        this.waiter = { resolve, reject, timer };
      }));
    if (packet.header.messageType === T.ERROR) throw new Error(String(packet.json?.['code']));
    return packet;
  }
}
export interface SavedDownload {
  url: string;
  name: string;
  sha256: string;
}
export class TransferClient {
  constructor(private readonly manager: ConnectionManager) {}
  private async cancel(id: bigint) {
    if (this.manager.isReady)
      await this.manager.requestPacket(T.CANCEL_TRANSFER, {}, id).catch(() => {});
  }
  async upload(
    file: File,
    progress: (state: TransferProgress) => void,
    signal: AbortSignal,
    checkpoint?: bigint,
  ) {
    if (file.size > MAX_FILE_BYTES) throw new Error('SIZE_LIMIT_EXCEEDED');
    const state: TransferProgress = {
      direction: 'upload',
      name: file.name,
      size: file.size,
      confirmed: 0,
      state: 'hashing',
    };
    progress({ ...state });
    const { sha256 } = await digest(await file.arrayBuffer(), false, signal);
    signal.throwIfAborted();
    const response = checkpoint
      ? await this.manager.requestPacket(T.RESUME_UPLOAD, { size: file.size, sha256 }, checkpoint)
      : await this.manager.requestPacket(T.UPLOAD_INIT, {
          name: file.name,
          size: file.size,
          sha256,
        });
    if (response.json?.['state'] === 'COMPLETED' && typeof response.json['fileId'] === 'string') {
      state.confirmed = file.size;
      state.state = 'completed';
      progress({ ...state });
      return response.json['fileId'];
    }
    const id = response.header.transferId;
    const inbox = new Inbox(this.manager, id, signal);
    try {
      state.confirmed = Number(response.header.offset);
      if (state.confirmed > file.size) throw new Error('Invalid upload checkpoint');
      state.state = 'transferring';
      progress({ ...state });
      for (let offset = state.confirmed; offset < file.size;) {
        const bytes = new Uint8Array(await file.slice(offset, offset + CHUNK_BYTES).arrayBuffer());
        const expected = offset + bytes.length;
        let acknowledged = false;
        for (let retry = 0; retry <= 3 && !acknowledged; retry++) {
          await this.manager.sendTransfer(T.FILE_CHUNK, bytes, id, offset, signal);
          try {
            for (;;) {
              const packet = await inbox.next();
              if (packet.header.messageType !== T.CHUNK_ACK)
                throw new Error('Invalid upload acknowledgement');
              const received = Number(packet.header.offset);
              if (received <= offset) continue;
              if (received !== expected) throw new Error('Unexpected upload offset');
              acknowledged = true;
              break;
            }
          } catch (error) {
            if (
              !(error instanceof Error) ||
              error.message !== 'Acknowledgement timeout' ||
              retry === 3
            )
              throw error;
          }
        }
        offset = expected;
        state.confirmed = offset;
        progress({ ...state });
      }
      signal.throwIfAborted();
      state.state = 'verifying';
      progress({ ...state });
      const completed = await this.manager.requestPacket(
        T.TRANSFER_FINISH,
        {},
        id,
        BigInt(file.size),
      );
      if (
        Number(completed.header.offset) !== file.size ||
        typeof completed.json?.['fileId'] !== 'string'
      )
        throw new Error('Upload commit mismatch');
      state.state = 'completed';
      progress({ ...state });
      return completed.json['fileId'];
    } catch (error) {
      if (signal.reason === 'pause') {
        const paused = await this.manager.requestPacket(T.PAUSE_UPLOAD, {}, id);
        state.confirmed = Number(paused.header.offset);
        state.state = 'paused';
        progress({ ...state });
        return;
      }
      if (signal.aborted) await this.cancel(id);
      else if (
        this.manager.isReady &&
        error instanceof Error &&
        error.message === 'Acknowledgement timeout'
      ) {
        await this.manager.requestPacket(T.PAUSE_UPLOAD, {}, id).catch(() => {});
      }
      state.state = 'failed';
      progress({ ...state });
      throw error;
    } finally {
      inbox.dispose();
    }
  }
  async download(
    file: FileRecord,
    progress: (state: TransferProgress) => void,
    signal: AbortSignal,
  ): Promise<SavedDownload> {
    const state: TransferProgress = {
      direction: 'download',
      name: file.name,
      size: file.size,
      confirmed: 0,
      state: 'transferring',
    };
    progress({ ...state });
    const response = await this.manager.requestPacket(T.DOWNLOAD_INIT, { fileId: file.fileId });
    const id = response.header.transferId;
    const metadata = response.json!;
    if (
      metadata['fileId'] !== file.fileId ||
      metadata['size'] !== file.size ||
      metadata['sha256'] !== file.sha256 ||
      file.size > MAX_FILE_BYTES
    ) {
      await this.cancel(id);
      throw new Error('Download metadata mismatch');
    }
    const inbox = new Inbox(this.manager, id, signal);
    const bytes = new Uint8Array(file.size);
    try {
      await this.manager.sendTransfer(T.CHUNK_ACK, new Uint8Array(), id, 0, signal);
      for (;;) {
        const packet = await inbox.next(45000);
        if (packet.header.messageType === T.FILE_CHUNK) {
          const offset = Number(packet.header.offset),
            end = offset + packet.payload.length;
          if (end > file.size) throw new Error('Download exceeded declared size');
          if (offset === state.confirmed) {
            bytes.set(packet.payload, offset);
            state.confirmed = end;
            progress({ ...state });
          } else if (end > state.confirmed) throw new Error('Unexpected download offset');
          await this.manager.sendTransfer(
            T.CHUNK_ACK,
            new Uint8Array(),
            id,
            state.confirmed,
            signal,
          );
        } else if (packet.header.messageType === T.TRANSFER_FINISH) {
          if (state.confirmed !== file.size || Number(packet.header.offset) !== file.size)
            throw new Error('Incomplete download');
          break;
        } else throw new Error('Unexpected download packet');
      }
      state.state = 'verifying';
      progress({ ...state });
      const result = await digest(bytes.buffer, true, signal);
      if (result.sha256 !== file.sha256 || !result.buffer) {
        await this.manager.sendTransfer(
          T.ERROR,
          { code: 'HASH_MISMATCH', message: 'Download hash mismatch' },
          id,
          file.size,
          signal,
        );
        throw new Error('HASH_MISMATCH');
      }
      await this.manager.sendTransfer(T.RESULT, { fileId: file.fileId }, id, file.size, signal);
      const url = URL.createObjectURL(
        new Blob([result.buffer], { type: 'application/octet-stream' }),
      );
      state.state = 'completed';
      progress({ ...state });
      return { url, name: file.name, sha256: result.sha256 };
    } catch (error) {
      state.state = 'failed';
      progress({ ...state });
      await this.cancel(id);
      throw error;
    } finally {
      inbox.dispose();
    }
  }
}
