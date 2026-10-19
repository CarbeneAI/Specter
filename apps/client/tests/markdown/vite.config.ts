import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// Isolated component fixture: no application entry, credentials, or API proxies.
export default defineConfig({
  plugins: [vue()],
  envDir: false,
  server: { hmr: false, host: '127.0.0.1', port: 4179, strictPort: true },
});
