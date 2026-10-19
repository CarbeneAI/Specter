import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mock } from 'bun:test';
import type { WazuhAlert } from '../src/types';

const scenario = process.argv[2];
const root = mkdtempSync(join(tmpdir(), 'specter-poll-single-flight-'));
delete process.env.WAZUH_CA_FILE;
delete process.env.WAZUH_INSECURE_TLS;
process.env.WAZUH_DASHBOARD_URL = 'https://wazuh.single-flight.invalid';
process.env.WAZUH_DASHBOARD_USER = 'synthetic-reader';
process.env.WAZUH_DASHBOARD_PASSWORD = 'synthetic-not-a-secret';
process.env.WAZUH_ALERTS_PATH = join(root, 'no-such-alerts.jsonl');
process.env.WAZUH_POLL_INTERVAL = scenario === 'repeated-start' ? '12345' : '30000';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; });
  return { promise, resolve };
}
const heldFetch = deferred<Response>();
const heldJson = deferred<unknown>();
const heldScoring = deferred<WazuhAlert[]>();
const intervals: { callback: () => Promise<void>; delay: number | undefined }[] = [];
const originalInterval = globalThis.setInterval;
const originalFetch = globalThis.fetch;
// Capture the real scheduled callback; never install a short or long live timer.
globalThis.setInterval = ((callback: () => Promise<void>, delay?: number) => {
  intervals.push({ callback, delay });
  return intervals.length as unknown as ReturnType<typeof setInterval>;
}) as typeof setInterval;
const tick = () => intervals[0].callback();
const settle = () => new Promise<void>(resolve => setImmediate(resolve));

const queries: { query: { bool: { must: unknown[] } } }[] = [];
let reentrantStart: (() => void) | undefined;
let reentrantStarts = 0;
let fetchCalls = 0;
let scoreCalls = 0;
let pendingScore: WazuhAlert[] = [];
function body(sequence: number) {
  return { timed_out: false, _shards: { total: 1, successful: 1, failed: 0 }, hits: { hits: [{ _source: {
    timestamp: `2026-10-19T12:00:0${sequence}.000Z`,
    rule: { id: 'synthetic-rule', level: 7, description: `row ${sequence}` },
    agent: { id: '001', name: 'synthetic-agent' },
  } }] } };
}
// No real provider, database, SSH, file watcher or HTTP dependency is called.
mock.module('../src/scorer', () => ({
  scoreAndAttach: async (alerts: WazuhAlert[]) => {
    scoreCalls++;
    if (scoreCalls === 1 && scenario === 'overlap-scoring') {
      pendingScore = alerts;
      return heldScoring.promise;
    }
    if (scoreCalls === 1 && scenario === 'scorer-error') throw new Error('synthetic scoring failure');
    return alerts;
  },
}));
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.origin, 'https://wazuh.single-flight.invalid');
  assert.equal(url.pathname, '/api/console/proxy');
  assert.equal(url.searchParams.get('path'), 'wazuh-alerts-*/_search');
  fetchCalls++;
  queries.push(JSON.parse(String(init?.body)));
  if (fetchCalls === 1) {
    if (scenario === 'repeated-start') {
      assert.ok(reentrantStart);
      reentrantStart();
    }
    if (scenario === 'overlap-fetch' || scenario === 'repeated-start') return heldFetch.promise;
    if (scenario === 'fetch-error') throw new Error('synthetic fetch failure');
    if (scenario === 'http-error') return new Response(null, { status: 503 });
    if (scenario === 'empty-response') return Response.json({ timed_out: false, _shards: { total: 1, successful: 1, failed: 0 }, hits: { hits: [] } });
    if (scenario === 'json-error') return new Response('{invalid JSON');
    if (scenario === 'mapping-error') return Response.json({ timed_out: false, _shards: { total: 1, successful: 1, failed: 0 }, hits: { hits: [{ _source: null }] } });
    if (scenario === 'overlap-response') {
      const response = Response.json({});
      Object.defineProperty(response, 'json', { value: () => heldJson.promise });
      return response;
    }
  }
  return Response.json(body(fetchCalls));
}) as typeof fetch;

try {
  const { startAlertIngestion, getRecentAlerts } = await import('../src/alert-ingest');
  reentrantStart = () => { reentrantStarts++; startAlertIngestion(); };
  const batches: WazuhAlert[][] = [];
  let reentered: Promise<void> | undefined;
  startAlertIngestion(alerts => {
    batches.push(alerts);
    if (batches.length === 1 && scenario === 'storage-reentry') reentered = tick();
    if (batches.length === 1 && scenario === 'callback-error') throw new Error('synthetic subscriber failure');
  });
  await settle();
  assert.equal(intervals.length, 1);
  assert.equal(intervals[0].delay, scenario === 'repeated-start' ? 12345 : 30000);

  if (scenario === 'repeated-start') {
    assert.equal(reentrantStarts, 1, 'first fetch must synchronously reenter the real start API');
    startAlertIngestion();
    startAlertIngestion();
    assert.equal(intervals.length, 1, 'repeated starts must not register more timers');
    assert.equal(fetchCalls, 1, 'repeated starts must not trigger another initial poll');
  }
  if (['overlap-fetch', 'overlap-response', 'overlap-scoring', 'repeated-start'].includes(scenario)) {
    await tick(); await tick(); await tick();
    assert.equal(fetchCalls, 1, 'ticks during any pending poll stage must be skipped');
    assert.equal(batches.length, 0);
    assert.equal(getRecentAlerts().length, 0);
    if (scenario === 'overlap-fetch' || scenario === 'repeated-start') heldFetch.resolve(Response.json(body(1)));
    if (scenario === 'overlap-response') heldJson.resolve(body(1));
    if (scenario === 'overlap-scoring') {
      assert.equal(scoreCalls, 1);
      heldScoring.resolve(pendingScore);
    }
    await settle();
    assert.equal(fetchCalls, 1, 'skipped ticks must not queue or replay after settlement');
    assert.equal(batches.length, 1);
    if (scenario === 'repeated-start') {
      startAlertIngestion();
      assert.equal(intervals.length, 1);
      assert.equal(fetchCalls, 1, 'a settled service must not be restarted by another start call');
    }
    await tick();
    assert.equal(fetchCalls, 2);
    assert.equal(batches.length, 2);
    assert.equal(getRecentAlerts().length, 2);
    assert.deepEqual(queries[1].query.bool.must.find(condition =>
      condition !== null && typeof condition === 'object' && 'range' in condition),
      { range: { timestamp: { gt: '2026-10-19T12:00:01.000Z' } } },
      'the next scheduled request retains the accepted newest timestamp');
  } else if (scenario === 'storage-reentry') {
    await reentered;
    assert.equal(fetchCalls, 1, 'the guard must remain held through subscriber/store callbacks');
    assert.equal(batches.length, 1);
    await tick();
    assert.equal(fetchCalls, 2);
    assert.equal(batches.length, 2);
  } else {
    assert.ok(['fetch-error', 'http-error', 'json-error', 'mapping-error', 'scorer-error', 'callback-error', 'empty-response'].includes(scenario));
    assert.equal(fetchCalls, 1);
    if (scenario === 'callback-error') {
      assert.equal(getRecentAlerts().length, 1, 'subscriber failure does not roll back the stored batch');
      assert.equal(getRecentAlerts()[0].rule.description, 'row 1');
    }
    await tick();
    assert.equal(fetchCalls, 2, 'a settled failure or empty response must release the guard');
    const expectedRows = scenario === 'callback-error' ? 2 : 1;
    assert.equal(getRecentAlerts().length, expectedRows);
    assert.equal(batches.length, expectedRows);
    assert.equal(getRecentAlerts()[0].rule.description, 'row 2');
  }
} finally {
  globalThis.fetch = originalFetch;
  globalThis.setInterval = originalInterval;
  rmSync(root, { recursive: true, force: true });
}
