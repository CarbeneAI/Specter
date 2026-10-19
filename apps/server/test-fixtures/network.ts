import assert from 'node:assert/strict';
import { mock } from 'bun:test';
import { fileURLToPath } from 'node:url';

const scenario = process.argv[2];
for (const key of ['SPECTER_API_HOST', 'SPECTER_CLIENT_HOST', 'SPECTER_ALLOWED_HOSTS', 'CORS_ALLOWED_ORIGIN', 'CLIENT_PORT', 'VITE_API_URL', 'VITE_WS_URL']) delete process.env[key];
process.env.PORT = '0';
if (scenario === 'configured') {
  process.env.SPECTER_API_HOST = '0.0.0.0';
  process.env.SPECTER_ALLOWED_HOSTS = 'dashboard.example.test,api.example.test';
  process.env.CORS_ALLOWED_ORIGIN = 'https://dashboard.example.test';
}
if (scenario === 'invalid-config') process.env.CORS_ALLOWED_ORIGIN = '*';

// Mock every startup/route dependency in this child process. No provider, SSH,
// feed, JSONL or database code is imported, and every client connects to loopback.
let effects = 0;
let starts = 0;
let ledgerLimit: number | undefined;
const effect = () => { effects++; return []; };
mock.module('../src/alert-ingest', () => ({
  startAlertIngestion: () => { starts++; }, getRecentAlerts: effect, getAlertStats: effect,
  getFilterOptions: effect, filterAlerts: effect, addAlerts: effect, getScoredAlerts: effect,
}));
mock.module('../src/pai-client', () => ({ sendChatMessage: effect, searchWazuhAlerts: effect, getOllamaModels: effect, QUICK_PROMPTS: [] }));
mock.module('../src/suricata-suppression', () => ({ suppressSuricataRule: () => { effects++; return { success: true }; }, getSuppressedSIDs: effect }));
mock.module('../src/mutes', () => ({ createMute: () => { effects++; return { success: true }; }, deleteMute: effect, listMutes: effect }));
mock.module('../src/ledger', () => ({ listInvestigations: (limit: number) => { ledgerLimit = limit; return effect(); }, getInvestigation: effect }));
const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.hostname, '127.0.0.1', 'fixture HTTP requests must stay on loopback');
  return originalFetch(input, init);
}) as typeof fetch;

if (scenario === 'invalid-config') {
  await assert.rejects(import('../src/index'), /CORS_ALLOWED_ORIGIN/);
  assert.equal(starts, 0, 'invalid configuration must fail before ingestion');
  process.exit(0);
}
const { server } = await import('../src/index');
const base = `http://127.0.0.1:${server.port}`;
let vite: { close(): Promise<void> } | undefined;
let closing: Promise<void> | undefined;
const cleanup = () => closing ??= (async () => { await vite?.close(); server.stop(true); })();
// The parent timeout must also stop the Node Vite child, even on fixture failure.
process.once('SIGTERM', () => { void cleanup().finally(() => process.exit(143)); });

async function socket(baseUrl: string, headers: Record<string, string>, accept: boolean) {
  const before = effects;
  const frames: any[] = [];
  await new Promise<void>((resolve, reject) => {
    const ws = new WebSocket(baseUrl.replace('http:', 'ws:') + '/stream', { headers });
    const timer = setTimeout(() => { ws.close(); reject(new Error(`WebSocket fixture timed out: ${JSON.stringify({ headers, accept, frames })}`)); }, 2500);
    ws.onopen = () => {
      if (!accept) { clearTimeout(timer); ws.close(); reject(new Error('forbidden upgrade accepted')); return; }
      ws.send(JSON.stringify({ type: 'ping' }));
      ws.send(JSON.stringify({ type: 'filter', limit: 3 }));
    };
    ws.onmessage = event => {
      frames.push(JSON.parse(String(event.data)));
      if (frames.length === 4) ws.close();
    };
    ws.onerror = () => { if (accept) { clearTimeout(timer); reject(new Error('allowed upgrade rejected')); } };
    ws.onclose = () => { clearTimeout(timer); resolve(); };
  });
  if (accept) {
    assert.deepEqual(frames.map(frame => frame.type), ['initial', 'stats', 'pong', 'filtered']);
    assert.equal(effects, before + 3);
  } else {
    assert.equal(frames.length, 0, 'denied sockets must receive no initial data');
    assert.equal(effects, before, 'denied sockets must not reach open/filter handlers');
  }
}

try {
  assert.equal(starts, 1);
  if (scenario === 'default-bind') {
    assert.equal(server.hostname, '127.0.0.1');
    assert.equal((await fetch(base + '/health')).status, 200);
  } else if (scenario === 'denials') {
    for (const headers of [
      { Host: 'evil.test', Origin: 'http://127.0.0.1:5173' },
      { Host: '127.0.0.2', Origin: 'http://127.0.0.1:5173' },
      { Host: 'localhost,evil.test' }, { Host: 'user@localhost' },
      { Origin: 'https://evil.test' }, { Origin: 'null' },
      { 'Sec-Fetch-Site': 'cross-site' }, { 'Sec-Fetch-Site': 'same-site' },
    ] as Record<string, string>[]) {
      for (const [method, path, body] of [
        ['GET', '/settings/ollama-models', undefined],
        ['POST', '/alerts/ingest', '[{}]'], ['POST', '/alerts/suppress', '{"ruleId":"1"}'],
        ['POST', '/alerts/mutes', '{"ruleId":"1"}'], ['POST', '/chat', '{"message":"hi"}'],
        ['OPTIONS', '/alerts/ingest', undefined],
      ]) {
        const before = effects;
        const response = await fetch(base + path, { method, headers: { ...headers, 'X-Authentik-Username': 'forged' }, body });
        assert.equal(response.status, 403, `${method} ${path} ${JSON.stringify(headers)}`);
        assert.equal(response.headers.has('Access-Control-Allow-Origin'), false);
        assert.equal(effects, before);
      }
    }
    const cli = await fetch(base + '/alerts/ingest', { method: 'POST', body: '[{}]' });
    assert.equal(cli.status, 200);
    assert.equal(effects, 1);
    const browser = await fetch(base + '/settings/ollama-models', { headers: { Origin: 'http://127.0.0.1:5173' } });
    assert.equal(browser.status, 200);
    assert.equal(browser.headers.get('Access-Control-Allow-Origin'), 'http://127.0.0.1:5173');
    const preflight = await fetch(base + '/alerts/ingest', { method: 'OPTIONS', headers: { Origin: 'http://127.0.0.1:5173' } });
    assert.equal(preflight.status, 204);
    assert.equal(effects, 2);
  } else if (scenario === 'configured') {
    assert.equal(server.hostname, '0.0.0.0');
    const headers = { Host: 'api.example.test', Origin: 'https://dashboard.example.test' };
    assert.equal((await fetch(base + '/health', { headers })).status, 200);
    await socket(base, headers, true);
  } else if (scenario === 'websockets') {
    await socket(base, { Origin: 'https://evil.test' }, false);
    await socket(base, { Host: 'evil.test', Origin: 'http://127.0.0.1:5173' }, false);
    await socket(base, { 'Sec-Fetch-Site': 'cross-site' }, false);
    await socket(base, { Origin: 'http://127.0.0.1:5173' }, true);
    await socket(base, {}, true);
  } else if (scenario === 'vite' || scenario === 'vite-preview' || scenario === 'vite-command') {
    // Actual Vite config and proxy on custom ephemeral ports. No browser, HMR,
    // outside requests or package auto-install is involved.
    process.env.SPECTER_API_HOST = '127.0.0.1';
    process.env.SPECTER_CLIENT_HOST = '127.0.0.1';
    process.env.SPECTER_ALLOWED_HOSTS = 'localhost';
    process.env.PORT = String(server.port);
    process.env.CLIENT_PORT = '0';
    process.env.CORS_ALLOWED_ORIGIN = 'http://127.0.0.1:5173';
    const clientRoot = fileURLToPath(new URL('../../client', import.meta.url));
    const argv = scenario === 'vite-command'
      ? [process.execPath, '--no-env-file', 'run', 'dev', '--config', 'test-fixtures/vite-cli.config.ts']
      : ['node', 'test-fixtures/vite.mjs', scenario === 'vite-preview' ? 'preview' : 'dev'];
    const child = Bun.spawn(argv, { cwd: clientRoot, env: process.env, stdout: 'pipe', stderr: 'pipe' });
    const errors = new Response(child.stderr).text();
    vite = { close: async () => {
      child.kill();
      const deadline = setTimeout(() => child.kill(9), 1500);
      try { await child.exited; await errors; } finally { clearTimeout(deadline); }
    } };
    const reader = child.stdout.getReader();
    let output = '';
    while (!/FIXTURE_PORT=(\d+)/.test(output)) {
      const chunk = await reader.read();
      if (chunk.done) throw new Error('Vite exited without listening');
      output += new TextDecoder().decode(chunk.value);
    }
    if (scenario === 'vite-command') {
      assert.match(output, /FIXTURE_BUN=false/, 'bun run dev must honor Vite Node shebang');
      assert.ok(Number(output.match(/FIXTURE_NODE=(\d+)/)?.[1]) >= 22);
    }
    const proxied = `http://127.0.0.1:${output.match(/FIXTURE_PORT=(\d+)/)![1]}`;
    assert.equal((await fetch(proxied + '/api/health')).status, 200);
    assert.equal((await fetch(proxied + '/')).status, 200);
    const ledger = await fetch(proxied + '/api/ledger?limit=7');
    assert.deepEqual(await ledger.json(), { investigations: [] });
    assert.equal(ledgerLimit, 7);
    const before = effects;
    await fetch(proxied + '/apix/ledger?limit=8');
    assert.equal(effects, before, '/apix must not be proxied');
    for (const headers of [
      { Host: '127.0.0.2', Origin: 'http://127.0.0.1:5173' },
      { Host: 'evil.test', Origin: 'http://127.0.0.1:5173' },
      { Origin: 'https://evil.test' },
    ] as Record<string, string>[]) {
      assert.equal((await fetch(proxied + '/', { headers })).status, 403);
      assert.equal((await fetch(proxied + '/api/settings/ollama-models', { headers })).status, 403);
      assert.equal(effects, before);
      await socket(proxied, headers, false);
    }
    await socket(proxied, { Origin: 'http://127.0.0.1:5173' }, true);
  } else throw new Error(`Unknown scenario ${scenario}`);
} finally {
  await cleanup();
}
