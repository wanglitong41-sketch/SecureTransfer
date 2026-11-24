import { readFileSync } from 'node:fs';
import { Agent } from 'node:https';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

const certificatePath = (name: string) =>
  fileURLToPath(new URL('../../runtime/certs/' + name, import.meta.url));

export default defineConfig(({ command }) => ({
  plugins: [vue()],
  server:
    command === 'serve'
      ? {
          host: '127.0.0.1',
          port: 5173,
          strictPort: true,
          https: {
            cert: readFileSync(certificatePath('server-cert.pem')),
            key: readFileSync(certificatePath('server-key.pem')),
            minVersion: 'TLSv1.3',
          },
          proxy: {
            '/api': {
              target: 'https://localhost:8443',
              agent: new Agent({ ca: readFileSync(certificatePath('ca-cert.pem')) }),
            },
          },
        }
      : {},
}));
