/// <reference types="vitest/config" />
import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The frontend's own version (package.json, set by scripts/release.py), shown in
// the sidebar footer. Read here so the build and the vitest runs agree on it.
const { version: appVersion } = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf-8'),
) as { version: string }

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  server: {
    port: 5173,
    proxy: {
      // Host-based `npm run dev`: the app container's port is published to
      // 127.0.0.1:8000, so the default reaches it. The containerized
      // `frontend-dev` compose service (ADR-0054) sets VITE_API_PROXY_TARGET
      // to the compose service DNS name (http://app:8000) instead, since a
      // container's own `localhost` never reaches a sibling container.
      '/api': {
        target: process.env.VITE_API_PROXY_TARGET || 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
  },
})
