import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: parseInt(process.env.FRONTEND_PORT || '5173'),
    host: '127.0.0.1', // FIX: was 'true' (all interfaces). Use localhost only unless LAN access needed.
  }
})
