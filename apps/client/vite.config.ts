import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    port: parseInt(process.env.CLIENT_PORT || '5173'),
    strictPort: true,
    host: true,
    allowedHosts: ['.home.carbeneai.com', 'localhost'],
    proxy: {
      '/alerts': 'http://localhost:4001',
      '/chat': 'http://localhost:4001',
      '/settings': 'http://localhost:4001',
      '/health': 'http://localhost:4001',
      '/stream': { target: 'http://localhost:4001', ws: true, changeOrigin: true },
    },
  },
})
