import { defineConfig, type Plugin } from 'vite';
import config from '../vite.config';

// Exercise the real package command with the real config, while disabling HMR
// and reporting an ephemeral port without depending on Vite's terminal format.
const listening: Plugin = {
  name: 'local-cli-fixture',
  configureServer(server) {
    server.httpServer?.once('listening', () => {
      const address = server.httpServer!.address();
      if (!address || typeof address === 'string') throw new Error('Expected TCP fixture address');
      console.log(`FIXTURE_NODE=${process.versions.node}`);
      console.log(`FIXTURE_BUN=${'bun' in process.versions}`);
      console.log(`FIXTURE_PORT=${address.port}`);
    });
  },
};
export default defineConfig(async env => {
  const base = await config(env);
  return { ...base, plugins: [...base.plugins || [], listening], server: { ...base.server, hmr: false } };
});
