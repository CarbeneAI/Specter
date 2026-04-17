import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: parseInt(process.env.CLIENT_PORT || '5173'),
    strictPort: true,
    host: true,
  },
})
