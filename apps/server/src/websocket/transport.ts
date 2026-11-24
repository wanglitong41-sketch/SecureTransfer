import { setTimeout as delay } from 'node:timers/promises';
import type { PublicKeys } from '../auth/public-keys.js';
import type { PublicKeyProof } from '@securetransfer/protocol';
import type { TransferService, TransferContext } from '../transfer/service.js';
import { randomUUID } from 'node:crypto';
import type { Server } from 'node:https';
import { WebSocket, WebSocketServer } from 'ws';
import {
  MESSAGE_TYPES as T,
  MAX_MESSAGE_BYTES,
  decodeMessage,
  encodeMessage,
  ProtocolError,
  validateClientRequest,
} from '@securetransfer/protocol';
import type { ProtocolMessage, ErrorCode, JsonObject } from '@securetransfer/protocol';
import type { AuthService, Identity } from '../auth/service.js';
import type { FileService } from '../files/service.js';

export interface TransportEvent {
  event: string;
  connectionId?: string;
  userId?: string;
  fileId?: string;
  errorCode?: string;
  messageType?: number;
  status?: number;
  requestId?: number;
  code?: number;
  transferId?: string;
  direction?: 'upload' | 'download';
  activeTransfers?: number;
}
export interface TransportOptions {
  allowedOrigins: readonly string[];
  heartbeatMs: number;
  authenticationMs: number;
  maxConnections: number;
  requestsPerSecond: number;
  sessionSweepMs: number;
  auditAvailable: () => boolean;
  onEvent: (event: TransportEvent) => void;
}
export const DEFAULT_TRANSPORT_OPTIONS: TransportOptions = {
  allowedOrigins: ['https://localhost:8443'],
  heartbeatMs: 20000,
  authenticationMs: 10000,
  maxConnections: 20,
  requestsPerSecond: 20,
  sessionSweepMs: 20000,
  auditAvailable: () => true,
  onEvent: () => {},
};
interface Peer {
  identity: Identity | undefined;
  close: (code: number, reason: string) => void;
}

export function attachTransport(
  server: Server,
  auth: AuthService,
  keys: PublicKeys,
  files: FileService,
  transfers: TransferService,
  overrides: Partial<TransportOptions> = {},
) {
  const options = { ...DEFAULT_TRANSPORT_OPTIONS, ...overrides };
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_MESSAGE_BYTES,
    perMessageDeflate: false,
  });
  const peers = new Map<WebSocket, Peer>();
  const jobs = new Set<Promise<void>>();
  let stopping = false;
  let socketsClosed: Promise<void> | undefined;
  server.on('secureConnection', (socket) => socket.setKeepAlive(true, 20000));
  server.on('upgrade', (request, socket, head) => {
    const reject = (code: number, label: string) => {
      options.onEvent({ event: 'upgrade_rejected', status: code });
      return socket.end(
        'HTTP/1.1 ' + code + ' ' + label + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n',
      );
    };
    if (!options.auditAvailable()) return reject(503, 'Unavailable');
    if (stopping) return reject(503, 'Unavailable');
    if (request.url !== '/ws') return reject(404, 'Not Found');
    if (!request.headers.origin || !options.allowedOrigins.includes(request.headers.origin))
      return reject(403, 'Forbidden');
    if (
      wss.clients.size >= options.maxConnections ||
      [...peers.values()].filter((peer) => !peer.identity).length >= 5
    )
      return reject(503, 'Unavailable');
    wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, request));
  });
  wss.on('connection', (ws, request) => {
    const connectionId = randomUUID();
    let alive = true,
      windowStarted = Date.now(),
      count = 0,
      bulkCount = 0;
    const controller = new AbortController();
    let closeTimer: ReturnType<typeof setTimeout> | undefined;
    let authTimer: ReturnType<typeof setTimeout>;
    let registered = false;
    let extendedChallenge = false;
    const openedAt = Date.now();
    const origin = request.headers.origin!;
    const ip = request.socket.remoteAddress ?? 'local';
    const emit = (event: string, extra: Partial<TransportEvent> = {}) =>
      options.onEvent({
        event,
        connectionId,
        ...(peer.identity ? { userId: peer.identity.userId } : {}),
        ...extra,
      });
    const close = (code: number, reason: string) => {
      ws.close(code, reason);
      closeTimer ??= setTimeout(() => ws.terminate(), 1000);
    };
    const peer: Peer = { identity: undefined, close };
    peers.set(ws, peer);
    emit('connected');
    const startDeadline = (duration = options.authenticationMs) => {
      clearTimeout(authTimer);
      authTimer = setTimeout(() => {
        emit('authentication_timeout');
        close(1008, 'Authentication required');
      }, duration);
    };
    startDeadline();
    const send = (packet: Uint8Array) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      if (ws.bufferedAmount >= 1024 * 1024) {
        close(1008, 'Send buffer limit');
        return;
      }
      ws.send(packet, { binary: true }, (error) => {
        if (error) ws.terminate();
      });
    };
    const result = (message: ProtocolMessage, body: JsonObject, transferId = 0n, offset = 0) =>
      send(encodeMessage(T.RESULT, message.header.requestId, body, transferId, BigInt(offset)));
    const context = (): TransferContext => ({
      connectionId,
      userId: peer.identity!.userId,
      signal: controller.signal,
      assertActive() {
        controller.signal.throwIfAborted();
        if (!peer.identity || ws.readyState !== WebSocket.OPEN)
          throw new ProtocolError('Connection closed', 'UNAUTHORIZED');
        if (!options.auditAvailable())
          throw new ProtocolError('Audit unavailable', 'INTERNAL_ERROR');
        auth.check(peer.identity.sessionHash);
      },
      async send(packet) {
        controller.signal.throwIfAborted();
        if (ws.bufferedAmount >= 1024 * 1024) {
          const started = Date.now();
          while (ws.bufferedAmount > 256 * 1024) {
            if (Date.now() - started > 30000) {
              close(1008, 'Send buffer timeout');
              throw new Error('Send buffer timeout');
            }
            await delay(10, undefined, { signal: controller.signal });
          }
        }
        if (ws.readyState !== WebSocket.OPEN) throw new Error('Connection closed');
        await new Promise<void>((resolve, reject) =>
          ws.send(packet, { binary: true }, (error) => (error ? reject(error) : resolve())),
        );
      },
      event(event, transferId, direction, activeTransfers) {
        emit(event, { transferId, direction, activeTransfers });
      },
    });
    const fail = (
      message: ProtocolMessage | undefined,
      code: ErrorCode,
      text: string,
      expectedOffset?: number,
    ) => {
      emit('request_rejected', {
        errorCode: code,
        ...(message
          ? { requestId: message.header.requestId, messageType: message.header.messageType }
          : {}),
      });
      return send(
        encodeMessage(
          T.ERROR,
          message?.header.requestId ?? 0,
          { code, message: text, ...(expectedOffset === undefined ? {} : { expectedOffset }) },
          message?.header.transferId ?? 0n,
        ),
      );
    };
    const bindIdentity = (identity: Identity) => {
      if (
        [...peers.values()].filter((other) => other.identity?.userId === identity.userId).length >=
        3
      ) {
        throw new ProtocolError('User connection limit reached', 'RATE_LIMITED');
      }
      peer.identity = identity;
      clearTimeout(authTimer);
      emit('authenticated');
    };
    const bindSession = (session: ReturnType<AuthService['issueSession']>) => {
      const hash = auth.hashToken(session.token);
      if (ws.readyState !== WebSocket.OPEN || stopping) {
        auth.revoke(hash);
        return false;
      }
      try {
        bindIdentity(auth.check(hash));
      } catch (error) {
        auth.revoke(hash);
        throw error;
      }
      keys.clear(connectionId);
      return true;
    };
    const heartbeat = setInterval(() => {
      if (!alive) {
        emit('heartbeat_timeout');
        ws.terminate();
        return;
      }
      if (ws.readyState !== WebSocket.OPEN) return;
      alive = false;
      ws.ping();
      emit('ping');
    }, options.heartbeatMs);
    ws.on('pong', () => {
      alive = true;
      emit('pong');
    });
    ws.on('error', () => emit('socket_error'));
    ws.on('close', (code) => {
      clearTimeout(authTimer);
      clearInterval(heartbeat);
      clearTimeout(closeTimer);
      controller.abort();
      keys.clear(connectionId);
      transfers.disconnect(connectionId);
      peers.delete(ws);
      emit('closed', { code });
    });

    let chain = Promise.resolve();
    const transferChains = new Map<bigint, Promise<void>>();
    const pendingIds = new Set<number>();
    let pendingCount = 0;
    const handle = async (message: ProtocolMessage) => {
      if (stopping || ws.readyState !== WebSocket.OPEN) return;
      if (!options.auditAvailable()) {
        close(1011, 'Audit unavailable');
        return;
      }
      try {
        if (peer.identity) auth.check(peer.identity.sessionHash);
        validateClientRequest(message, peer.identity ? 'AUTHENTICATED' : 'CONNECTED');
        const body = message.json ?? {};
        switch (message.header.messageType) {
          case T.PROBE:
            result(message, { sequence: body['sequence'], connectionId, stage: 6 });
            emit('probe', { requestId: message.header.requestId });
            return;
          case T.REGISTER: {
            const registeredUser = await auth.register(
              String(body['username']),
              String(body['password']),
            );
            if (ws.readyState !== WebSocket.OPEN || stopping) return;
            emit('registered', { userId: registeredUser.userId });
            result(message, registeredUser);
            if (!registered) {
              registered = true;
              startDeadline();
            }
            return;
          }
          case T.LOGIN: {
            const session = await auth.login(
              String(body['username']),
              String(body['password']),
              request.socket.remoteAddress ?? 'local',
            );
            if (bindSession(session)) result(message, session);
            return;
          }
          case T.KEY_CHALLENGE:
            if (peer.identity) {
              const identity = peer.identity;
              const challenge = keys.enroll(
                connectionId,
                origin,
                identity.username,
                identity.userId,
                String(body['publicKeySpki']),
                String(body['label']),
              );
              result(message, { ...challenge });
            } else {
              if (extendedChallenge)
                throw new ProtocolError('Challenge already issued', 'RATE_LIMITED');
              const username = String(body['username']);
              auth.limitLogin(username, ip);
              const challenge = keys.login(connectionId, origin, username, String(body['keyId']));
              extendedChallenge = true;
              startDeadline(Math.max(1, Math.min(60000, openedAt + 70000 - Date.now())));
              result(message, { ...challenge });
            }
            return;
          case T.KEY_LOGIN: {
            const pending = keys.verifyProof(
              connectionId,
              origin,
              body as unknown as PublicKeyProof,
              'login',
            );
            const session = auth.issueSession(pending.userId);
            if (bindSession(session)) result(message, session);
            return;
          }
          case T.KEY_ENROLL: {
            const identity = peer.identity!;
            const pending = keys.verifyProof(
              connectionId,
              origin,
              body as unknown as PublicKeyProof,
              'enroll',
              identity.userId,
            );
            await auth.verifyPassword(identity.username, String(body['password']), ip);
            context().assertActive();
            result(message, keys.save(pending));
            emit('key_enrolled');
            return;
          }
          case T.KEY_LIST:
            result(message, { items: keys.list(peer.identity!.userId) });
            return;
          case T.KEY_REMOVE: {
            const identity = peer.identity!;
            await auth.verifyPassword(identity.username, String(body['password']), ip);
            context().assertActive();
            keys.remove(identity.userId, String(body['keyId']));
            emit('key_revoked');
            result(message, {});
            for (const other of peers.values()) {
              if (other.identity?.userId === identity.userId) other.close(1000, 'Session ended');
            }
            return;
          }
          case T.AUTH_RESUME: {
            const identity = auth.check(auth.hashToken(String(body['token'])));
            bindIdentity(identity);
            auth.check(identity.sessionHash, true);
            result(message, {
              userId: identity.userId,
              username: identity.username,
              expiresAt: new Date(identity.expiresAt).toISOString(),
            });
            return;
          }
          case T.LOGOUT: {
            const sessionHash = peer.identity!.sessionHash;
            auth.revoke(sessionHash);
            emit('logged_out');
            result(message, {});
            for (const other of peers.values())
              if (other.identity?.sessionHash === sessionHash) other.close(1000, 'Session ended');
            return;
          }
          case T.LIST_FILES:
            result(message, files.list(peer.identity!.userId, body['after'] as string | undefined));
            auth.check(peer.identity!.sessionHash, true);
            return;
          case T.DELETE_FILE:
            result(message, files.delete(peer.identity!.userId, String(body['fileId'])));
            emit('file_deleted', { fileId: String(body['fileId']) });
            auth.check(peer.identity!.sessionHash, true);
            return;
          case T.UPLOAD_INIT: {
            const task = transfers.initUpload(
              context(),
              String(body['name']),
              Number(body['size']),
              String(body['sha256']),
            );
            result(message, { chunkSize: 65536, state: 'ACTIVE' }, task.id);
            auth.check(peer.identity!.sessionHash, true);
            return;
          }
          case T.LIST_UPLOADS:
            result(
              message,
              transfers.listUploads(peer.identity!.userId, body['after'] as string | undefined),
            );
            return;
          case T.PAUSE_UPLOAD: {
            const id = message.header.transferId;
            const offset = transfers.pauseUpload(context(), id);
            result(message, { state: 'PAUSED' }, id, offset);
            return;
          }
          case T.RESUME_UPLOAD: {
            const id = message.header.transferId;
            const task = transfers.resumeUpload(
              context(),
              id,
              Number(body['size']),
              String(body['sha256']),
            );
            result(message, { ...task }, id, task.offset);
            return;
          }
          case T.DOWNLOAD_INIT: {
            const task = transfers.initDownload(context(), String(body['fileId']));
            result(
              message,
              {
                fileId: task.fileId,
                name: task.name,
                size: task.size,
                sha256: task.sha256,
                chunkSize: 65536,
              },
              task.id,
            );
            auth.check(peer.identity!.sessionHash, true);
            return;
          }
          case T.FILE_CHUNK: {
            const offset = await transfers.uploadChunk(context(), message);
            send(
              encodeMessage(
                T.CHUNK_ACK,
                0,
                new Uint8Array(),
                message.header.transferId,
                BigInt(offset),
              ),
            );
            auth.check(peer.identity!.sessionHash, true);
            return;
          }
          case T.CHUNK_ACK:
            await transfers.acknowledge(
              context(),
              message.header.transferId,
              Number(message.header.offset),
            );
            auth.check(peer.identity!.sessionHash, true);
            return;
          case T.TRANSFER_FINISH: {
            const completed = await transfers.finishUpload(
              context(),
              message.header.transferId,
              Number(message.header.offset),
            );
            result(
              message,
              { fileId: completed.fileId },
              message.header.transferId,
              completed.size,
            );
            auth.check(peer.identity!.sessionHash, true);
            return;
          }
          case T.RESULT:
          case T.ERROR:
            transfers.completeDownload(context(), message);
            return;
          case T.CANCEL_TRANSFER: {
            const offset = transfers.cancel(context(), message.header.transferId);
            result(message, { state: 'CANCELLED' }, message.header.transferId, offset);
            return;
          }
        }
      } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') return;
        const issue =
          error instanceof ProtocolError
            ? error
            : new ProtocolError('Request could not be completed', 'INTERNAL_ERROR');
        fail(message, issue.code, issue.message, issue.expectedOffset);
        if (
          issue.code === 'UNAUTHORIZED' &&
          (peer.identity ||
            message.header.messageType === T.LOGIN ||
            message.header.messageType === T.KEY_LOGIN ||
            message.header.messageType === T.KEY_CHALLENGE ||
            message.header.messageType === T.AUTH_RESUME)
        ) {
          emit('authentication_rejected');
          close(1008, 'Session invalid');
        } else if (issue.code === 'INVALID_MESSAGE' || issue.code === 'INTERNAL_ERROR')
          close(1002, 'Invalid request');
      }
    };
    ws.on('message', (data, binary) => {
      if (stopping || ws.readyState !== WebSocket.OPEN) return;
      let message: ProtocolMessage | undefined;
      try {
        if (!binary) throw new ProtocolError('Binary message required');
        const bytes = Array.isArray(data)
          ? Buffer.concat(data)
          : data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : data;
        message = decodeMessage(bytes);
        if (Date.now() - windowStarted >= 1000) {
          windowStarted = Date.now();
          count = 0;
          bulkCount = 0;
        }
        const bulk =
          message.header.messageType === T.FILE_CHUNK || message.header.messageType === T.CHUNK_ACK;
        const overLimit = bulk ? ++bulkCount > 256 : ++count > options.requestsPerSecond;
        if (overLimit || pendingCount >= 16) {
          fail(message, 'RATE_LIMITED', 'Request limit exceeded');
          close(1008, 'Request limit exceeded');
          return;
        }
        if (message.header.requestId !== 0 && pendingIds.has(message.header.requestId))
          throw new ProtocolError('Duplicate pending request ID');
        if (message.header.requestId !== 0) pendingIds.add(message.header.requestId);
        pendingCount++;
        const current = message;
        const id = current.header.transferId;
        const taskMessage =
          id !== 0n &&
          ![T.PAUSE_UPLOAD, T.CANCEL_TRANSFER, T.RESUME_UPLOAD].some(
            (type) => type === current.header.messageType,
          );
        const waitsForTask = taskMessage || current.header.messageType === T.RESUME_UPLOAD;
        const previous = waitsForTask ? Promise.all([chain, transferChains.get(id)]) : chain;
        const work = previous
          .then(() => handle(current))
          .finally(() => {
            pendingIds.delete(current.header.requestId);
            pendingCount--;
          });
        if (taskMessage) transferChains.set(id, work);
        else chain = work;
        jobs.add(work);
        void work.finally(() => {
          jobs.delete(work);
          if (taskMessage && transferChains.get(id) === work) transferChains.delete(id);
        });
      } catch {
        fail(message, 'INVALID_MESSAGE', 'Invalid binary message');
        close(1002, 'Invalid message');
      }
    });
  });
  const sweep = setInterval(() => {
    for (const peer of peers.values()) {
      if (!peer.identity) continue;
      try {
        auth.check(peer.identity.sessionHash);
      } catch {
        peer.close(1008, 'Session expired');
      }
    }
    auth.cleanupExpired();
  }, options.sessionSweepMs);
  const shutdown = () => {
    if (stopping) return;
    stopping = true;
    clearInterval(sweep);
    transfers.shutdown();
    for (const ws of wss.clients) ws.terminate();
    socketsClosed = new Promise<void>((resolve) => wss.close(() => resolve()));
  };
  server.once('close', shutdown);
  return {
    shutdown,
    drain: async () => {
      await Promise.allSettled([...jobs]);
      await socketsClosed;
    },
    clients: wss.clients,
  };
}
