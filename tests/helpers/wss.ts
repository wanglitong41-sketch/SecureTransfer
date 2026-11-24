import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { once } from 'node:events';
import { WebSocket } from 'ws';
import type { ClientOptions, RawData } from 'ws';
import type { AddressInfo } from 'node:net';
import { testRuntime } from './runtime.js';
import { UNLIMITED_FLOW } from '../../apps/server/src/transfer/flow-control.js';
import type { TransferOptions } from '../../apps/server/src/transfer/service.js';
import type { AuthOptions } from '../../apps/server/src/auth/service.js';
import { createApp } from '../../apps/server/src/app.js';
import { PROJECT_ROOT } from '../../apps/server/src/config.js';
import type {
  TransportOptions,
  TransportEvent,
} from '../../apps/server/src/websocket/transport.js';
import { decodeMessage, encodeMessage, MESSAGE_TYPES as T } from '@securetransfer/protocol';

export async function startTransport(
  options: Partial<TransportOptions> = {},
  authOptions: Partial<AuthOptions> = {},
  transferOptions: Partial<TransferOptions> = {},
  runtime = testRuntime(),
) {
  const events: TransportEvent[] = [];
  const server = await createApp(
    runtime.config,
    {
      ...options,
      onEvent: (event) => events.push(event),
    },
    authOptions,
    { flow: UNLIMITED_FLOW, ...transferOptions },
  );
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = (server.address() as AddressInfo).port;
  const ca = await readFile(join(PROJECT_ROOT, 'runtime/certs/ca-cert.pem'));
  const clients: WebSocket[] = [];
  function connect(overrides: ClientOptions = {}, path = '/ws') {
    const ws = new WebSocket('wss://localhost:' + port + path, {
      ca,
      origin: 'https://localhost:8443',
      ...overrides,
    });
    ws.on('error', () => {});
    clients.push(ws);
    return ws;
  }
  return {
    server,
    dataRoot: runtime.config.dataRoot,
    events,
    connect,
    async stop(removeRuntime = true) {
      for (const ws of clients) ws.terminate();
      server.shutdownWebSockets();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await server.resourcesClosed;
      if (removeRuntime) runtime.cleanup();
    },
  };
}
export function dataBytes(data: RawData) {
  return Array.isArray(data)
    ? Buffer.concat(data)
    : data instanceof ArrayBuffer
      ? new Uint8Array(data)
      : data;
}
export async function probe(ws: WebSocket, sequence: number, requestId = sequence) {
  const result = once(ws, 'message');
  ws.send(encodeMessage(T.PROBE, requestId, { sequence }));
  const [data] = (await result) as [RawData];
  return decodeMessage(dataBytes(data));
}

let nextId = 100;
export async function rpc(
  ws: WebSocket,
  type: import('@securetransfer/protocol').MessageType,
  body: import('@securetransfer/protocol').JsonObject = {},
  transferId = 0n,
  offset = 0n,
) {
  const id = nextId++;
  const reply = once(ws, 'message');
  ws.send(encodeMessage(type, id, body, transferId, offset));
  const message = decodeMessage(dataBytes((await reply)[0]));
  if (message.header.requestId !== id) throw new Error('Unexpected RPC correlation');
  return message;
}
export async function createUser(ws: WebSocket, username = 'alice') {
  const password = 'fixture-stage-three';
  const registered = await rpc(ws, T.REGISTER, { username, password });
  if (registered.header.messageType !== T.RESULT) throw new Error('Test registration failed');
  const login = await rpc(ws, T.LOGIN, { username, password });
  if (login.header.messageType !== T.RESULT) throw new Error('Test login failed');
  return login.json!;
}
