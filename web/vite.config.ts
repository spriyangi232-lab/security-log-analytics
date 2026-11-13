import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // VITE_BASE lets the static demo live under a sub-path (GitHub Pages serves /<repo>/).
  base: process.env.VITE_BASE ?? '/',
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:8000' } },
  css: { preprocessorOptions: { scss: { api: 'modern-compiler', quietDeps: true } } },
  build: { chunkSizeWarningLimit: 2500 },
});
