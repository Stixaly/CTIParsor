/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
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
