import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Read VITE_* variables from the repo-root .env
  envDir: fileURLToPath(new URL('../../', import.meta.url)),
  server: { port: 5173 },
  preview: { port: 5173 },
  build: { target: 'es2022', sourcemap: true },
});
