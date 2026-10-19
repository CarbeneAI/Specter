import { fileURLToPath } from 'node:url';
import { expect, test } from 'bun:test';
import { resolveEndpoints } from './endpoints';

test('same-origin HTTP and HTTPS endpoints keep custom authority', () => {
  expect(resolveEndpoints({}, { protocol: 'http:', host: '127.0.0.1:5417' })).toEqual({ api: '/api', ws: 'ws://127.0.0.1:5417/stream' });
  expect(resolveEndpoints({}, { protocol: 'https:', host: 'dashboard.example.test' })).toEqual({ api: '/api', ws: 'wss://dashboard.example.test/stream' });
});
test('explicit API and WebSocket overrides retain their base paths', () => {
  expect(resolveEndpoints({ VITE_API_URL: 'https://api.example.test/specter/api/', VITE_WS_URL: 'wss://api.example.test/specter/stream' }, { protocol: 'https:', host: 'ui.example.test' })).toEqual({ api: 'https://api.example.test/specter/api', ws: 'wss://api.example.test/specter/stream' });
  expect(resolveEndpoints({ VITE_API_URL: '/specter/api/' }, { protocol: 'http:', host: '[::1]:5417' }).api).toBe('/specter/api');
});

test('ledger resolves relative API base and includes credentials on both requests', async () => {
  const fixture = new URL('../../test-fixtures/ledger.ts', import.meta.url);
  const child = Bun.spawn([process.execPath, '--no-env-file', fileURLToPath(fixture)], { stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
});
