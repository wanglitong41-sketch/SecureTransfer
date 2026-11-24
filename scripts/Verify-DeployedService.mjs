import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { once } from 'node:events';
import { randomBytes, createHash } from 'node:crypto';

const root = resolve(process.argv[2] ?? '');
const require = createRequire(join(root, 'package.json'));
const { WebSocket } = require('ws');
const {
  encodeMessage,
  decodeMessage,
  ERROR_CODES,
  MESSAGE_TYPES: T,
} = await import(pathToFileURL(join(root, 'packages/protocol/dist/index.js')).href);
const ws = new WebSocket('wss://localhost:8443/ws', {
  ca: await readFile(join(root, 'runtime/certs/ca-cert.pem')),
  origin: 'https://localhost:8443',
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
});
const controller = new AbortController();
const options = { signal: controller.signal };
const timeout = setTimeout(() => controller.abort(new Error('Timed out after 20 seconds.')), 20000);
ws.on('error', () => {});
ws.once('close', (code) => controller.abort(new Error('WebSocket closed with code ' + code + '.')));

let step = 'CONNECT';
let nextRequestId = 1;
async function request(type, requestId, body, transferId, offset) {
  step = Object.keys(T).find((name) => T[name] === type);
  const response = once(ws, 'message', options);
  ws.send(encodeMessage(type, requestId, body, transferId, offset));
  const [bytes] = await response;
  const packet = decodeMessage(new Uint8Array(bytes));
  if (packet.header.messageType === T.ERROR) {
    const code = packet.json?.code;
    throw new Error(ERROR_CODES.includes(code) ? code : 'Server returned a protocol error.');
  }
  return packet;
}

function exchange(type, body = {}, transferId = 0n, offset = 0n) {
  return request(type, nextRequestId++, body, transferId, offset);
}

function task(type, body, transferId, offset = 0n) {
  return request(type, 0, body, transferId, offset);
}

try {
  await once(ws, 'open', options);
  const username = 'acl_' + randomBytes(6).toString('hex');
  const password = randomBytes(24).toString('hex');
  await exchange(T.REGISTER, { username, password });
  await exchange(T.LOGIN, { username, password });
  const bytes = Buffer.from('restricted-account file transfer fixture');
  const hash = createHash('sha256').update(bytes).digest('hex');
  const upload = await exchange(T.UPLOAD_INIT, {
    name: 'acl-fixture.txt',
    size: bytes.length,
    sha256: hash,
  });
  const ack = await task(T.FILE_CHUNK, bytes, upload.header.transferId);
  if (ack.header.messageType !== T.CHUNK_ACK || ack.header.offset !== BigInt(bytes.length))
    throw new Error('Upload ACK mismatch');
  const finished = await exchange(
    T.TRANSFER_FINISH,
    {},
    upload.header.transferId,
    BigInt(bytes.length),
  );
  const fileId = finished.json.fileId;
  const download = await exchange(T.DOWNLOAD_INIT, { fileId });
  const chunk = await task(T.CHUNK_ACK, new Uint8Array(), download.header.transferId);
  if (chunk.header.messageType !== T.FILE_CHUNK) throw new Error('Download chunk missing');
  const receivedHash = createHash('sha256').update(chunk.payload).digest('hex');
  const ending = await task(
    T.CHUNK_ACK,
    new Uint8Array(),
    download.header.transferId,
    BigInt(bytes.length),
  );
  if (ending.header.messageType !== T.TRANSFER_FINISH || receivedHash !== hash)
    throw new Error('Download integrity mismatch');
  ws.send(encodeMessage(T.RESULT, 0, { fileId }, download.header.transferId, BigInt(bytes.length)));
  await exchange(T.DELETE_FILE, { fileId });
  await exchange(T.LOGOUT);
  console.log(
    JSON.stringify({
      result: 'PASS',
      bytes: bytes.length,
      expectedSha256: hash,
      receivedSha256: receivedHash,
      tlsVerified: true,
    }),
  );
} catch (error) {
  const details = error.name === 'AbortError' ? error.cause : error;
  const reason =
    details.code === 'ECONNREFUSED'
      ? 'Connection refused on port 8443. Start the deployment first.'
      : (details.code ?? details.message);
  console.error('Deployment probe failed at ' + step + ': ' + reason);
  process.exitCode = 1;
} finally {
  clearTimeout(timeout);
  ws.terminate();
}
