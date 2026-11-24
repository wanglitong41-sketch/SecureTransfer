import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { WebSocket, RawData } from 'ws';
import {
  MESSAGE_TYPES as T,
  CHUNK_BYTES,
  encodeMessage,
  decodeMessage,
} from '@securetransfer/protocol';
import type { ProtocolMessage } from '@securetransfer/protocol';
import { rpc, dataBytes } from './wss.js';

export const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
export class WireInbox {
  private queue: ProtocolMessage[] = [];
  private waiting:
    | {
        resolve: (packet: ProtocolMessage) => void;
        reject: (error: Error) => void;
        timer: ReturnType<typeof setTimeout>;
      }
    | undefined;
  private receive = (data: RawData) => {
    const packet = decodeMessage(dataBytes(data));
    if (packet.header.requestId !== 0 || packet.header.transferId !== this.id) return;
    if (this.waiting) {
      const waiter = this.waiting;
      this.waiting = undefined;
      clearTimeout(waiter.timer);
      waiter.resolve(packet);
    } else this.queue.push(packet);
  };
  constructor(
    private readonly ws: WebSocket,
    private readonly id: bigint,
  ) {
    ws.on('message', this.receive);
  }
  async next() {
    return (
      this.queue.shift() ??
      new Promise<ProtocolMessage>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.waiting = undefined;
          reject(new Error('Wire timeout'));
        }, 5000);
        this.waiting = { resolve, reject, timer };
      })
    );
  }
  dispose() {
    this.ws.off('message', this.receive);
    if (this.waiting) {
      clearTimeout(this.waiting.timer);
      this.waiting.reject(new Error('Closed'));
    }
  }
}
export async function wireSend(
  ws: WebSocket,
  type: import('@securetransfer/protocol').MessageType,
  content: Uint8Array | import('@securetransfer/protocol').JsonObject,
  id: bigint,
  offset = 0,
) {
  await delay(6);
  ws.send(encodeMessage(type, 0, content, id, BigInt(offset)));
}
export async function beginUpload(
  ws: WebSocket,
  bytes: Uint8Array,
  name = 'fixture.bin',
  hash = sha256(bytes),
) {
  const created = await rpc(ws, T.UPLOAD_INIT, { name, size: bytes.length, sha256: hash });
  if (created.header.messageType !== T.RESULT) throw new Error(String(created.json?.['code']));
  return created.header.transferId;
}
export async function uploadBytes(
  ws: WebSocket,
  bytes: Uint8Array,
  name = 'fixture.bin',
  hash = sha256(bytes),
) {
  const id = await beginUpload(ws, bytes, name, hash);
  const inbox = new WireInbox(ws, id);
  try {
    for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
      const block = bytes.subarray(offset, Math.min(bytes.length, offset + CHUNK_BYTES));
      await wireSend(ws, T.FILE_CHUNK, block, id, offset);
      const ack = await inbox.next();
      if (
        ack.header.messageType !== T.CHUNK_ACK ||
        Number(ack.header.offset) !== offset + block.length
      ) {
        throw new Error(String(ack.json?.['code'] ?? 'Invalid ACK'));
      }
    }
    const completed = await rpc(ws, T.TRANSFER_FINISH, {}, id, BigInt(bytes.length));
    if (completed.header.messageType !== T.RESULT)
      throw new Error(String(completed.json?.['code']));
    return { fileId: String(completed.json?.['fileId']), transferId: id };
  } finally {
    inbox.dispose();
  }
}
export async function downloadBytes(ws: WebSocket, fileId: string) {
  const created = await rpc(ws, T.DOWNLOAD_INIT, { fileId });
  if (created.header.messageType !== T.RESULT) throw new Error(String(created.json?.['code']));
  const id = created.header.transferId,
    inbox = new WireInbox(ws, id),
    blocks: Uint8Array[] = [];
  let offset = 0;
  try {
    await wireSend(ws, T.CHUNK_ACK, new Uint8Array(), id);
    for (;;) {
      const packet = await inbox.next();
      if (packet.header.messageType === T.ERROR) throw new Error(String(packet.json?.['code']));
      if (packet.header.messageType === T.TRANSFER_FINISH) break;
      if (packet.header.messageType !== T.FILE_CHUNK || Number(packet.header.offset) !== offset)
        throw new Error('Invalid download offset');
      blocks.push(packet.payload);
      offset += packet.payload.length;
      await wireSend(ws, T.CHUNK_ACK, new Uint8Array(), id, offset);
    }
    const bytes = Buffer.concat(blocks);
    const valid =
      bytes.length === created.json?.['size'] && sha256(bytes) === created.json?.['sha256'];
    await wireSend(
      ws,
      valid ? T.RESULT : T.ERROR,
      valid ? { fileId } : { code: 'HASH_MISMATCH', message: 'Test hash mismatch' },
      id,
      offset,
    );
    if (!valid) throw new Error('HASH_MISMATCH');
    return bytes;
  } finally {
    blocks.length = 0;
    inbox.dispose();
  }
}
