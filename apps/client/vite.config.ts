import { defineConfig, loadEnv, type Plugin, type Connect } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'
import { readNetworkPolicy, requestIsAllowed, type NetworkPolicy } from '../server/src/network-policy'

// Vite's built-in host check permits all IPs. Apply the same exact admission
// policy as the API before HTTP middleware, including preview requests.
function boundary(policy: NetworkPolicy): Plugin {
  const install = (server: { middlewares: Connect.Server }) => {
    server.middlewares.use((req, res, next) => {
      const headers = new Headers()
      for (const [key, value] of Object.entries(req.headers)) {
        if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(',') : String(value))
      }
      if (!requestIsAllowed({ headers }, policy)) {
        res.writeHead(403, { Vary: 'Origin' })
        res.end('Forbidden')
        return
      }
      next()
    })
  }
  return { name: 'specter-network-boundary', configureServer: install, configurePreviewServer: install }
}

export default defineConfig(({ mode }) => {
  const envDir = fileURLToPath(new URL('../..', import.meta.url))
  const env = { ...loadEnv(mode, envDir, ''), ...process.env }
  const policy = readNetworkPolicy(env)
  const apiHost = policy.hostname === '0.0.0.0' ? '127.0.0.1' : policy.hostname === '::' ? '::1' : policy.hostname
  const target = `http://${apiHost.includes(':') ? `[${apiHost}]` : apiHost}:${policy.port}`
  const proxy = {
    '^/api(?:/|$)': { target, changeOrigin: false, rewrite: (path: string) => path.replace(/^\/api(?=\/|$)/, '') || '/' },
    // Preserve both authority and browser Origin for the API's upgrade check.
    '^/stream$': { target, ws: true, changeOrigin: false },
  }
  return {
    envDir,
    plugins: [boundary(policy), vue()],
    server: {
      host: policy.clientHostname, port: policy.clientPort, strictPort: true,
      allowedHosts: [...policy.allowedHosts], proxy,
    },
    preview: {
      host: policy.clientHostname, port: policy.clientPort, strictPort: true,
      allowedHosts: [...policy.allowedHosts], proxy,
    },
  }
})
