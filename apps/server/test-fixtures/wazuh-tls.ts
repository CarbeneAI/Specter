import assert from 'node:assert/strict';
import { join } from 'node:path';

const [scenario, directory] = process.argv.slice(2);
for (const key of ['WAZUH_CA_FILE', 'WAZUH_INSECURE_TLS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) {
  delete process.env[key];
}
process.env.NO_PROXY = '*';
process.env.WAZUH_DASHBOARD_USER = 'fixture-user';
process.env.WAZUH_DASHBOARD_PASSWORD = 'fixture-password';
process.env.WAZUH_ALERTS_PATH = join(directory, 'does-not-exist.jsonl');
process.env.WAZUH_POLL_INTERVAL = '60000';
process.env.LEDGER_DB_PATH = join(directory, 'unused-ledger.sqlite');
process.env.SPECTER_ENV_FILE = join(directory, 'does-not-exist.env');

const cert = scenario === 'hostname-mismatch' ? 'wrong-host' : 'valid';
let requests = 0;
let redirectedRequests = 0;
const handlerErrors: Error[] = [];
const redirected = Bun.serve({
  hostname: '127.0.0.1', port: 0,
  fetch() { redirectedRequests++; return Response.json({}); },
});
const server = Bun.serve({
  hostname: '127.0.0.1', port: 0,
  ...(scenario === 'http-rejected' ? {} : {
    tls: { key: Bun.file(join(directory, `${cert}.key`)), cert: Bun.file(join(directory, `${cert}.pem`)) },
  }),
  async fetch(req) {
    requests++;
    assert.equal(req.method, 'POST');
    assert.equal(req.headers.get('Authorization'), `Basic ${Buffer.from('fixture-user:fixture-password').toString('base64')}`);
    assert.equal(req.headers.get('osd-xsrf'), 'true');
    const url = new URL(req.url);
    assert.equal(url.pathname, '/wazuh/api/console/proxy');
    assert.equal(url.searchParams.get('path'), 'wazuh-alerts-*/_search');
    assert.equal(url.searchParams.get('method'), 'POST');
    await req.json();
    if (scenario.startsWith('redirect-')) return Response.redirect(`http://127.0.0.1:${redirected.port}/redirected`, 307);
    return Response.json({
      timed_out: false, _shards: { total: 1, successful: 1, failed: 0, skipped: 0 },
      hits: { total: { value: 1, relation: 'eq' }, hits: [{ _source: {
        timestamp: new Date().toISOString(),
        rule: { level: 5, id: '100', description: 'Synthetic TLS fixture' },
        agent: { id: '001', name: 'fixture' },
      } }] },
    });
  },
  error(error) {
    handlerErrors.push(error);
    return new Response('fixture handler failed', { status: 500 });
  },
});
const protocol = scenario === 'http-rejected' ? 'http' : 'https';
process.env.WAZUH_DASHBOARD_URL = `${protocol}://127.0.0.1:${server.port}/wazuh`;
if (!['untrusted-default', 'explicit-insecure', 'unrelated-https-stays-verified', 'redirect-insecure', 'http-rejected'].includes(scenario)) {
  process.env.WAZUH_CA_FILE = join(directory, 'ca.pem');
}
if (['explicit-insecure', 'unrelated-https-stays-verified', 'redirect-insecure', 'conflicting-options'].includes(scenario)) process.env.WAZUH_INSECURE_TLS = 'true';
if (scenario === 'invalid-ca') process.env.WAZUH_CA_FILE = join(directory, 'invalid.pem');
if (scenario === 'missing-ca') process.env.WAZUH_CA_FILE = join(directory, 'missing.pem');
if (scenario === 'relative-ca') process.env.WAZUH_CA_FILE = 'ca.pem';
if (scenario === 'non-ca-certificate') process.env.WAZUH_CA_FILE = join(directory, 'valid.pem');
if (scenario === 'invalid-insecure-value') process.env.WAZUH_INSECURE_TLS = 'yes';
if (scenario === 'url-credentials') process.env.WAZUH_DASHBOARD_URL = `https://embedded:password@127.0.0.1:${server.port}/wazuh`;
if (scenario === 'url-query') process.env.WAZUH_DASHBOARD_URL += '?unexpected=1';

const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.hostname, '127.0.0.1', 'fixture may only contact its disposable servers');
  return originalFetch(input, init);
}) as typeof fetch;

let exitCode = 0;
try {
  const { searchWazuhAlerts } = await import('../src/pai-client');
  const { startAlertIngestion, getRecentAlerts } = await import('../src/alert-ingest');
  const success = ['private-ca', 'explicit-insecure', 'unrelated-https-stays-verified'].includes(scenario);
  const result = await searchWazuhAlerts({});
  if (success) {
    assert.equal(result.error, undefined, result.error ?? 'direct search must succeed');
    assert.equal(result.total, 1);
    assert.equal(requests, 1);
  } else {
    assert.ok(result.error, 'unsafe or invalid transport must produce a direct-search failure');
    assert.equal(requests, scenario.startsWith('redirect-') ? 1 : 0);
    if (scenario.includes('-ca') || scenario === 'non-ca-certificate') assert.match(result.error, /WAZUH_CA_FILE/);
  }

  // Observe completion of the real initial poll. Timers and any file watchers
  // live only in this disposable process, which exits before another poll.
  const originalLog = console.log;
  const complete = new Promise<void>(resolve => {
    console.log = (...args) => {
      originalLog(...args);
      if (String(args[0]).startsWith('Initial poll complete')) resolve();
    };
  });
  startAlertIngestion();
  await complete;
  console.log = originalLog;
  assert.equal(getRecentAlerts().length, success ? 1 : 0, 'polling must use the same transport policy as direct search');
  assert.equal(requests, success || scenario.startsWith('redirect-') ? 2 : 0);

  if (scenario === 'unrelated-https-stays-verified') {
    await assert.rejects(originalFetch(`https://127.0.0.1:${server.port}/unrelated`), 'the Wazuh exception must not change global TLS verification');
    assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, undefined);
    assert.equal(requests, 2);
  }
  assert.equal(redirectedRequests, 0, 'redirect targets must never receive a request');
  assert.deepEqual(handlerErrors, [], 'a fixture handler failure must not masquerade as transport rejection');
} catch (error) {
  console.error(error);
  exitCode = 1;
} finally {
  server.stop(true);
  redirected.stop(true);
}
process.exit(exitCode);
