import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();

try {
  const server = await createApp(config);
  server.on('error', (error) => {
    console.error('Server failed:', error.message);
    server.shutdownWebSockets();
    server.close();
    process.exitCode = 1;
  });
  server.listen(config.port, config.host, () => {
    console.log('SecureTransfer HTTPS ready at https://localhost:' + config.port);
  });
  const stop = () => {
    server.shutdownWebSockets();
    server.close(() => {
      process.exitCode = 0;
    });
    server.closeIdleConnections();
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
} catch (error) {
  console.error('Startup failed:', error instanceof Error ? error.message : error);
  console.error('Run npm run setup:certs and npm run build before npm run start.');
  process.exitCode = 1;
}
