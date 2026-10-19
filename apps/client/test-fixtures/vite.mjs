import { createServer, preview } from 'vite';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const mode = process.argv[2];
const dist = mode === 'preview' ? mkdtempSync(join(tmpdir(), 'specter-preview-')) : undefined;
if (dist) writeFileSync(join(dist, 'index.html'), '<!doctype html><title>Local fixture</title>');
const server = dist
  ? await preview({ build: { outDir: dist } })
  : await createServer({ server: { hmr: false } });
if (!dist) await server.listen();
console.log('FIXTURE_PORT=' + server.httpServer.address().port);
process.on('SIGTERM', async () => {
  if (dist) { await new Promise(resolve => server.httpServer.close(resolve)); rmSync(dist, { recursive: true, force: true }); }
  else await server.close();
  process.exit(0);
});
