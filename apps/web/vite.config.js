import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import basicSsl from '@vitejs/plugin-basic-ssl';

const envDir = fileURLToPath(new URL('../../', import.meta.url));

export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, envDir, ''), ...process.env };
  const target = env.API_PROXY_TARGET || 'http://localhost:4000';
  // The browser talks to one origin; Vite forwards /api (and did:web documents) to the API.
  const proxy = { '/api': { target, changeOrigin: false, xfwd: true }, '/issuers': { target, changeOrigin: false, xfwd: true } };
  // WEB_HTTPS=1 serves over HTTPS with a self-signed cert. Browsers only expose WebCrypto on
  // https:// or localhost, so this is needed when opening the app from another device by LAN IP.
  const https = ['1', 'true'].includes(String(env.WEB_HTTPS).toLowerCase());
  return {
    plugins: [react(), ...(https ? [basicSsl({ name: 'blockcred-dev' })] : [])],
    envDir,
    server: { port: 5173, host: true, proxy },
    preview: { port: 5173, host: true, proxy },
    build: { target: 'es2022', sourcemap: true },
  };
});
