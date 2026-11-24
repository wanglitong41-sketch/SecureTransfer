export const PROTOCOL_MAGIC = 'SFT1';
export const PROTOCOL_VERSION = 1;
export const HEADER_BYTES = 32;
export const CHUNK_BYTES = 64 * 1024;
export const MAX_FILE_BYTES = 100 * 1024 * 1024;
export const MAX_MESSAGE_BYTES = 128 * 1024;
export const MAX_JSON_BYTES = 8 * 1024;

export const HEADER_FIELDS = [
  { name: 'magic', offset: 0, bytes: 4 },
  { name: 'version', offset: 4, bytes: 1 },
  { name: 'messageType', offset: 5, bytes: 1 },
  { name: 'flags', offset: 6, bytes: 2 },
  { name: 'requestId', offset: 8, bytes: 4 },
  { name: 'transferId', offset: 12, bytes: 8 },
  { name: 'offset', offset: 20, bytes: 8 },
  { name: 'payloadLength', offset: 28, bytes: 4 },
] as const;

export const MESSAGE_TYPES = {
  REGISTER: 0x01,
  LOGIN: 0x02,
  AUTH_RESUME: 0x03,
  LOGOUT: 0x04,
  PROBE: 0x05,
  KEY_CHALLENGE: 0x06,
  KEY_LOGIN: 0x07,
  KEY_ENROLL: 0x08,
  KEY_REMOVE: 0x09,
  KEY_LIST: 0x0a,
  LIST_FILES: 0x10,
  DELETE_FILE: 0x11,
  UPLOAD_INIT: 0x20,
  DOWNLOAD_INIT: 0x21,
  LIST_UPLOADS: 0x22,
  RESUME_UPLOAD: 0x23,
  PAUSE_UPLOAD: 0x24,
  CANCEL_TRANSFER: 0x25,
  FILE_CHUNK: 0x30,
  CHUNK_ACK: 0x31,
  TRANSFER_FINISH: 0x32,
  RESULT: 0x70,
  ERROR: 0x71,
} as const;

export type MessageType = (typeof MESSAGE_TYPES)[keyof typeof MESSAGE_TYPES];

export interface MessageHeader {
  version: number;
  messageType: MessageType;
  flags: number;
  requestId: number;
  transferId: bigint;
  offset: bigint;
  payloadLength: number;
}

export const ERROR_CODES = [
  'INVALID_MESSAGE',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'FILE_NOT_FOUND',
  'INVALID_OFFSET',
  'SIZE_LIMIT_EXCEEDED',
  'HASH_MISMATCH',
  'RATE_LIMITED',
  'TRANSFER_NOT_FOUND',
  'INVALID_STATE',
  'TASK_BUSY',
  'QUOTA_EXCEEDED',
  'USERNAME_TAKEN',
  'INTERNAL_ERROR',
  'NOT_IMPLEMENTED',
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];
export type JsonObject = { [key: string]: unknown };
export type ConnectionState = 'CONNECTED' | 'AUTHENTICATED' | 'CLOSED';

export interface ProtocolMessage {
  header: MessageHeader;
  payload: Uint8Array;
  json: JsonObject | null;
}

export interface FileRecord {
  fileId: string;
  name: string;
  size: number;
  sha256: string;
  createdAt: string;
}
export interface UserProfile {
  userId: string;
  username: string;
  expiresAt: string;
}
