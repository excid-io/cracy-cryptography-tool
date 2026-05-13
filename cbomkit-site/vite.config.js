import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/opa": {
        target: "http://localhost:8181",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/opa/, ""),
      },
    },
  },
});