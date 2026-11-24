import {
  PROTOCOL_MAGIC,
  PROTOCOL_VERSION,
  HEADER_BYTES,
  MAX_MESSAGE_BYTES,
  MAX_JSON_BYTES,
  MAX_FILE_BYTES,
  CHUNK_BYTES,
  MESSAGE_TYPES,
} from './definitions.js';
import type {
  MessageHeader,
  MessageType,
  JsonObject,
  ProtocolMessage,
  ErrorCode,
} from './definitions.js';

export class ProtocolError extends Error {
  constructor(
    message: string,
    public readonly code: ErrorCode = 'INVALID_MESSAGE',
    public readonly expectedOffset?: number,
  ) {
    super(message);
    this.name = 'ProtocolError';
  }
}

const knownTypes = new Set<number>(Object.values(MESSAGE_TYPES));
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function checkInteger(value: number, max: number, field: string) {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new ProtocolError('Invalid ' + field);
  }
}

export function decodeMessage(bytes: Uint8Array): ProtocolMessage {
  if (bytes.byteLength < HEADER_BYTES || bytes.byteLength > MAX_MESSAGE_BYTES) {
    throw new ProtocolError('Invalid message size');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (
    [...bytes.subarray(0, 4)].map((value) => String.fromCharCode(value)).join('') !==
      PROTOCOL_MAGIC ||
    view.getUint8(4) !== PROTOCOL_VERSION ||
    view.getUint16(6) !== 0 ||
    !knownTypes.has(view.getUint8(5))
  ) {
    throw new ProtocolError('Invalid protocol header');
  }
  const header: MessageHeader = {
    version: view.getUint8(4),
    messageType: view.getUint8(5) as MessageType,
    flags: view.getUint16(6),
    requestId: view.getUint32(8),
    transferId: view.getBigUint64(12),
    offset: view.getBigUint64(20),
    payloadLength: view.getUint32(28),
  };
  if (header.payloadLength !== bytes.byteLength - HEADER_BYTES) {
    throw new ProtocolError('Payload length mismatch');
  }
  if (header.offset > BigInt(MAX_FILE_BYTES)) throw new ProtocolError('Offset out of range');
  const payload = bytes.subarray(HEADER_BYTES);
  if (header.messageType === MESSAGE_TYPES.FILE_CHUNK) {
    if (
      payload.length === 0 ||
      payload.length > CHUNK_BYTES ||
      header.offset + BigInt(payload.length) > BigInt(MAX_FILE_BYTES)
    ) {
      throw new ProtocolError('Invalid file chunk size');
    }
    return { header, payload, json: null };
  }
  if (header.messageType === MESSAGE_TYPES.CHUNK_ACK) {
    if (payload.length !== 0) throw new ProtocolError('ACK payload must be empty');
    return { header, payload, json: null };
  }
  if (payload.length > MAX_JSON_BYTES) throw new ProtocolError('JSON payload too large');
  let json: unknown;
  try {
    json = JSON.parse(decoder.decode(payload));
  } catch {
    throw new ProtocolError('Invalid UTF-8 JSON');
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    throw new ProtocolError('JSON payload must be an object');
  }
  return { header, payload, json: json as JsonObject };
}

export function encodeMessage(
  messageType: MessageType,
  requestId: number,
  content: JsonObject | Uint8Array = {},
  transferId = 0n,
  offset = 0n,
): Uint8Array<ArrayBuffer> {
  checkInteger(messageType, 255, 'message type');
  checkInteger(requestId, 0xffffffff, 'request ID');
  if (
    transferId < 0n ||
    transferId > 0xffffffffffffffffn ||
    offset < 0n ||
    offset > BigInt(MAX_FILE_BYTES)
  ) {
    throw new ProtocolError('Invalid 64-bit field');
  }
  let payload: Uint8Array;
  try {
    payload = content instanceof Uint8Array ? content : encoder.encode(JSON.stringify(content));
  } catch {
    throw new ProtocolError('Payload is not JSON serializable');
  }
  if (payload.length > MAX_MESSAGE_BYTES - HEADER_BYTES)
    throw new ProtocolError('Payload too large');
  const result = new Uint8Array(HEADER_BYTES + payload.length);
  result.set(encoder.encode(PROTOCOL_MAGIC));
  const view = new DataView(result.buffer);
  view.setUint8(4, PROTOCOL_VERSION);
  view.setUint8(5, messageType);
  view.setUint32(8, requestId);
  view.setBigUint64(12, transferId);
  view.setBigUint64(20, offset);
  view.setUint32(28, payload.length);
  result.set(payload, HEADER_BYTES);
  decodeMessage(result);
  return result;
}
