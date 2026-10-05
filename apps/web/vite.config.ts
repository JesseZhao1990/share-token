import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  base: '/',
  build: { outDir: '../../dist/web', emptyOutDir: true, sourcemap: true },
  server: { host: '127.0.0.1', port: 5173, proxy: { '/control': 'http://127.0.0.1:8787', '/v1': 'http://127.0.0.1:8787' } },
});
