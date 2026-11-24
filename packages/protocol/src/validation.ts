import { MESSAGE_TYPES as T, MAX_FILE_BYTES, ERROR_CODES } from './definitions.js';
import type { ProtocolMessage, JsonObject, ConnectionState, MessageType } from './definitions.js';

import { ProtocolError } from './codec.js';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hash = /^[0-9a-f]{64}$/;
const offsetTypes: readonly MessageType[] = [
  T.FILE_CHUNK,
  T.CHUNK_ACK,
  T.TRANSFER_FINISH,
  T.RESULT,
  T.ERROR,
];
const authenticationTypes: readonly MessageType[] = [
  T.REGISTER,
  T.LOGIN,
  T.AUTH_RESUME,
  T.KEY_LOGIN,
];
const transferRequests = new Set<number>([
  T.RESUME_UPLOAD,
  T.PAUSE_UPLOAD,
  T.CANCEL_TRANSFER,
  T.FILE_CHUNK,
  T.CHUNK_ACK,
  T.TRANSFER_FINISH,
]);
function requireField(condition: boolean) {
  if (!condition) throw new ProtocolError('Invalid request fields');
}
function username(value: unknown) {
  return typeof value === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(value);
}
function password(value: unknown) {
  return (
    typeof value === 'string' &&
    value.length >= 8 &&
    value.length <= 128 &&
    new TextEncoder().encode(value).length <= 512
  );
}
function proof(body: JsonObject) {
  return (
    validFileId(body['challengeId']) &&
    validFileId(body['keyId']) &&
    typeof body['signatureBase64'] === 'string' &&
    /^[A-Za-z0-9+/]{86}==$/.test(body['signatureBase64'])
  );
}
function isSize(value: unknown) {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= MAX_FILE_BYTES
  );
}
function validFileId(value: unknown) {
  return typeof value === 'string' && uuid.test(value);
}

export function validateClientRequest(message: ProtocolMessage, state: ConnectionState) {
  const h = message.header;
  const j: JsonObject = message.json ?? {};
  if (state === 'CLOSED') throw new ProtocolError('Connection closed', 'INVALID_STATE');
  const zeroId =
    h.messageType === T.FILE_CHUNK ||
    h.messageType === T.CHUNK_ACK ||
    h.messageType === T.RESULT ||
    h.messageType === T.ERROR;
  requireField(zeroId ? h.requestId === 0 : h.requestId !== 0);
  const isTransfer = transferRequests.has(h.messageType) || zeroId;
  requireField(isTransfer ? h.transferId !== 0n : h.transferId === 0n);
  if (!offsetTypes.includes(h.messageType)) {
    requireField(h.offset === 0n);
  }
  switch (h.messageType) {
    case T.PROBE:
      requireField(
        Number.isInteger(j['sequence']) &&
          Number(j['sequence']) >= 0 &&
          Number(j['sequence']) <= 0xffffffff,
      );
      break;
    case T.REGISTER:
    case T.LOGIN:
      requireField(
        typeof j['username'] === 'string' &&
          /^[a-zA-Z0-9_]{3,32}$/.test(j['username']) &&
          typeof j['password'] === 'string' &&
          j['password'].length >= 8 &&
          j['password'].length <= 128 &&
          new TextEncoder().encode(j['password']).length <= 512,
      );
      break;
    case T.KEY_CHALLENGE:
      requireField(
        state === 'CONNECTED'
          ? username(j['username']) && validFileId(j['keyId'])
          : typeof j['publicKeySpki'] === 'string' &&
              /^[A-Za-z0-9+/]{60,180}={0,2}$/.test(j['publicKeySpki']) &&
              typeof j['label'] === 'string' &&
              j['label'].trim().length > 0 &&
              j['label'].length <= 48,
      );
      break;
    case T.KEY_LOGIN:
      requireField(proof(j));
      break;
    case T.KEY_ENROLL:
      requireField(proof(j) && password(j['password']));
      break;
    case T.KEY_REMOVE:
      requireField(validFileId(j['keyId']) && password(j['password']));
      break;
    case T.KEY_LIST:
      requireField(Object.keys(j).length === 0);
      break;
    case T.AUTH_RESUME:
      requireField(typeof j['token'] === 'string' && /^[a-f0-9]{64}$/.test(j['token']));
      break;
    case T.LIST_FILES:
      requireField(j['after'] === undefined || validFileId(j['after']));
      break;
    case T.LIST_UPLOADS:
      requireField(
        j['after'] === undefined ||
          (typeof j['after'] === 'string' &&
            /^[1-9][0-9]{0,19}$/.test(j['after']) &&
            BigInt(j['after']) <= 0xffffffffffffffffn),
      );
      break;
    case T.DELETE_FILE:
    case T.DOWNLOAD_INIT:
      requireField(validFileId(j['fileId']));
      break;
    case T.UPLOAD_INIT:
      requireField(
        typeof j['name'] === 'string' &&
          [...j['name']].length >= 1 &&
          [...j['name']].length <= 100 &&
          new TextEncoder().encode(j['name']).length <= 200 &&
          !/[\\/:<>"|?*]/.test(j['name']) &&
          !/[. ]$/.test(j['name']) &&
          !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(j['name'].split('.')[0]!.trimEnd()) &&
          [...j['name']].every(
            (character) => character.codePointAt(0)! > 31 && character.codePointAt(0)! !== 127,
          ) &&
          typeof j['size'] === 'number' &&
          Number.isSafeInteger(j['size']) &&
          j['size'] >= 0 &&
          typeof j['sha256'] === 'string' &&
          hash.test(j['sha256']),
      );
      if (Number(j['size']) > MAX_FILE_BYTES)
        throw new ProtocolError('File too large', 'SIZE_LIMIT_EXCEEDED');
      break;
    case T.RESUME_UPLOAD:
      requireField(isSize(j['size']) && typeof j['sha256'] === 'string' && hash.test(j['sha256']));
      break;
    case T.LOGOUT:
    case T.PAUSE_UPLOAD:
    case T.CANCEL_TRANSFER:
    case T.TRANSFER_FINISH:
      requireField(Object.keys(j).length === 0);
      break;
    case T.ERROR:
      requireField(
        ERROR_CODES.some((code) => code === j['code']) &&
          typeof j['message'] === 'string' &&
          j['message'].length <= 256,
      );
      break;
    case T.RESULT:
    case T.FILE_CHUNK:
    case T.CHUNK_ACK:
      break;
  }
  const publicTypes = new Set<number>([
    T.PROBE,
    T.REGISTER,
    T.LOGIN,
    T.AUTH_RESUME,
    T.KEY_CHALLENGE,
    T.KEY_LOGIN,
  ]);
  if (state === 'CONNECTED' && !publicTypes.has(h.messageType)) {
    throw new ProtocolError('Authentication required', 'UNAUTHORIZED');
  }
  if (state === 'AUTHENTICATED' && authenticationTypes.includes(h.messageType)) {
    throw new ProtocolError('Already authenticated', 'INVALID_STATE');
  }
}
