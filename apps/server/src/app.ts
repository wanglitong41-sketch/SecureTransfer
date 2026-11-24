import { AuditLogger } from './security/audit.js';
import { requireRegularFile } from './security/paths.js';
import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { extname, isAbsolute, relative, resolve } from 'node:path';
import { PROTOCOL_VERSION } from '@securetransfer/protocol';
import { UserBandwidth } from './transfer/flow-control.js';
import { PublicKeys } from './auth/public-keys.js';
import { TransferService } from './transfer/service.js';
import type { TransferOptions } from './transfer/service.js';
import { openStore } from './database/store.js';
import { AuthService } from './auth/service.js';
import type { AuthOptions } from './auth/service.js';
import { FileService } from './files/service.js';
import { attachTransport } from './websocket/transport.js';
import type { TransportOptions } from './websocket/transport.js';
import type { ServerConfig } from './config.js';

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

export async function createApp(
  config: ServerConfig,
  transportOptions: Partial<TransportOptions> = {},
  authOptions: Partial<AuthOptions> = {},
  transferOptions: Partial<TransferOptions> = {},
) {
  const audit = new AuditLogger(config.dataRoot);
  const [cert, key] = await Promise.all([
    readFile(config.certificatePath),
    readFile(config.keyPath),
  ]);
  const server = createServer(
    {
      cert,
      key,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      handshakeTimeout: 10000,
      maxHeaderSize: 16 * 1024,
      headersTimeout: 10000,
      requestTimeout: 15000,
      connectionsCheckingInterval: 1000,
    },
    (req, res) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; worker-src 'self'; connect-src 'self' wss://localhost:8443; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      );
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      if (!audit.healthy) {
        res.writeHead(503).end();
        return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        audit.write({ event: 'http_method_rejected', status: 405 });
        res.setHeader('Connection', 'close');
        res.writeHead(405, { Allow: 'GET, HEAD' }).end();
        return;
      }
      let pathname: string;
      try {
        pathname = decodeURIComponent(new URL(req.url ?? '/', 'https://localhost').pathname);
      } catch {
        audit.write({ event: 'http_path_rejected', status: 400 });
        res.writeHead(400).end();
        return;
      }
      if (pathname === '/api/health') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(
          req.method === 'HEAD'
            ? undefined
            : JSON.stringify({
                status: 'ok',
                stage: 6,
                protocolVersion: PROTOCOL_VERSION,
              }),
        );
        return;
      }
      const target = resolve(config.webRoot, pathname === '/' ? 'index.html' : '.' + pathname);
      const location = relative(config.webRoot, target);
      if (
        location.startsWith('..') ||
        isAbsolute(location) ||
        pathname.includes('\\') ||
        pathname.includes('\0')
      ) {
        audit.write({ event: 'http_path_rejected', status: 404 });
        res.writeHead(404).end();
        return;
      }
      try {
        requireRegularFile(config.webRoot, target);
      } catch {
        audit.write({ event: 'http_file_rejected', status: 404 });
        res.writeHead(404).end();
        return;
      }
      if (extname(target) === '.html') res.setHeader('Cache-Control', 'no-store');
      void readFile(target)
        .then((data) => {
          res.writeHead(200, {
            'Content-Type': CONTENT_TYPES[extname(target)] ?? 'application/octet-stream',
          });
          res.end(req.method === 'HEAD' ? undefined : data);
        })
        .catch((error: NodeJS.ErrnoException) => {
          res.writeHead(error.code === 'ENOENT' || error.code === 'EISDIR' ? 404 : 500).end();
        });
    },
  );
  server.on('secureConnection', (socket) => {
    const timer = setTimeout(() => {
      audit.write({ event: 'first_request_timeout', errorCode: 'HTTP_TIMEOUT' });
      socket.destroy();
    }, server.headersTimeout);
    const clear = () => clearTimeout(timer);
    socket.once('data', clear);
    socket.once('close', clear);
  });
  server.maxConnections = 50;
  server.maxRequestsPerSocket = 100;
  server.keepAliveTimeout = 5000;
  server.on('drop', () => audit.write({ event: 'tcp_limit_rejected' }));
  server.on('tlsClientError', () => audit.write({ event: 'tls_handshake_rejected' }));
  server.on('clientError', (error, socket) => {
    if ((error as NodeJS.ErrnoException).code === 'ERR_HTTP_REQUEST_TIMEOUT') {
      audit.write({ event: 'http_timeout_cleaned', errorCode: 'HTTP_TIMEOUT' });
      socket.destroy();
      return;
    }
    audit.write({ event: 'http_parser_rejected', status: 400 });
    if (socket.writable)
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  const database = openStore(config.dataRoot);
  const auth = new AuthService(database, authOptions);
  const files: FileService = new FileService(database, config.dataRoot, (id) =>
    transfers.isDownloading(id),
  );
  const transfers: TransferService = new TransferService(database, config.dataRoot, files, {
    flow: new UserBandwidth(config.bandwidth),
    ...transferOptions,
  });
  try {
    await transfers.initialize();
  } catch (error) {
    transfers.shutdown();
    database.close();
    throw error;
  }
  const transport = attachTransport(
    server,
    auth,
    new PublicKeys(database, auth.options.now),
    files,
    transfers,
    {
      allowedOrigins: config.development
        ? ['https://localhost:8443', 'https://localhost:5173']
        : ['https://localhost:8443'],
      ...transportOptions,
      auditAvailable: () => audit.healthy,
      onEvent: (event) => {
        audit.write(event);
        transportOptions.onEvent?.(event);
      },
    },
  );
  const resourcesClosed = new Promise<void>((resolve) => {
    server.once('close', () => {
      void transport.drain().then(() => {
        audit.close();
        database.close();
        resolve();
      });
    });
  });
  return Object.assign(server, { shutdownWebSockets: transport.shutdown, resourcesClosed });
}
