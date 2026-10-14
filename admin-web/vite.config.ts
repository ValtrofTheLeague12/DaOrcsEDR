import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The dev server proxies /api to the Python panel so the browser sees one
// origin in dev and in production alike. That matters beyond convenience:
// the analyzer REST API sends no CORS headers, so a cross-origin fetch from
// the browser would fail outright. Proxying is what makes it work at all.
const PANEL = process.env.ADMIN_PANEL ?? 'http://127.0.0.1:60100'

export default defineConfig({
  // Tailwind v4 ships as a Vite plugin and is configured in CSS
  // (@theme / @plugin), so there is no tailwind.config.js to keep in sync.
  plugins: [react(), tailwindcss()],
  server: {
    port: 60101,
    strictPort: true,
    proxy: {
      '/api': { target: PANEL, changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
})