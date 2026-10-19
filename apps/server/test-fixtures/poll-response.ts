import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cases, complete, source } from './poll-response-cases';
import { getScoringBackend, registerScoringBackend } from '../src/scorer';
import type { WazuhAlert } from '../src/types';

const scenario = cases.find(item => item.name === process.argv[2]);
assert.ok(scenario, 'unknown scenario');
const root = mkdtempSync(join(tmpdir(), 'specter-poll-response-'));
delete process.env.WAZUH_CA_FILE;
delete process.env.WAZUH_INSECURE_TLS;
process.env.WAZUH_DASHBOARD_URL = 'https://wazuh.poll-response.invalid';
process.env.WAZUH_DASHBOARD_USER = 'synthetic-reader';
process.env.WAZUH_DASHBOARD_PASSWORD = 'synthetic-not-a-secret';
process.env.WAZUH_ALERTS_PATH = join(root, 'no-such-alerts.jsonl');
process.env.WAZUH_POLL_INTERVAL = '30000';

const originalFetch = globalThis.fetch;
const originalInterval = globalThis.setInterval;
const originalError = console.error;
const intervals: (() => Promise<void>)[] = [];
const errors: string[] = [];
const queries: any[] = [];
let scoreCalls = 0;
const backend = getScoringBackend();
registerScoringBackend({ name: 'counted-real-scorer', score(item, context) {
  scoreCalls++;
  return backend.score(item, context);
} });
console.error = (...args: unknown[]) => { errors.push(args.map(String).join(' ')); };
globalThis.setInterval = ((callback: () => Promise<void>) => {
  intervals.push(callback);
  return intervals.length as unknown as ReturnType<typeof setInterval>;
}) as typeof setInterval;
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.origin, 'https://wazuh.poll-response.invalid');
  assert.equal(url.pathname, '/api/console/proxy');
  assert.equal(url.searchParams.get('path'), 'wazuh-alerts-*/_search');
  const query = JSON.parse(String(init?.body));
  assert.equal(query.size, 100);
  assert.deepEqual(query.sort, [{ timestamp: { order: 'desc' } }]);
  assert.equal(query.track_total_hits, undefined, 'poll does not require an expensive exact total');
  queries.push(query);
  if (queries.length === 1) return Response.json(complete([source(10)]));
  if (queries.length === 2) {
    return scenario.invalidJson ? new Response('{"PAYLOAD-CANARY":') : Response.json(scenario.body());
  }
  return Response.json(complete([source(13)]));
}) as typeof fetch;
const cursor = (i: number): string | undefined => queries[i].query.bool.must.find((v: any) => v.range)?.range.timestamp.gt;
try {
  const { startAlertIngestion, getRecentAlerts } = await import('../src/alert-ingest');
  const batches: WazuhAlert[][] = [];
  startAlertIngestion(items => batches.push(items));
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(intervals.length, 1);
  assert.equal(getRecentAlerts().length, 1);
  assert.equal(scoreCalls, 1);
  assert.equal(errors.length, 0);
  await intervals[0]!();
  assert.equal(cursor(1), source(10).timestamp);
  if (scenario.accept) {
    const rows = (scenario.body() as any).hits.hits;
    assert.equal(errors.length, 0, errors.join('\n'));
    assert.equal(getRecentAlerts().length, 1 + rows.length);
    assert.equal(scoreCalls, 1 + rows.length);
    assert.equal(batches.length, rows.length === 0 ? 1 : 2);
    if (rows.length > 0) {
      assert.deepEqual(batches[1]!.map(row => row.timestamp), rows.toReversed().map((row: any) => row._source.timestamp));
      assert.deepEqual(batches[1]!.map(row => row.id), [2, 3]);
    }
    await intervals[0]!();
    assert.equal(cursor(2), rows.length ? rows[0]._source.timestamp : source(10).timestamp);
  } else {
    assert.equal(scoreCalls, 1, 'rejected response must not score any row, including a valid first row');
    assert.equal(getRecentAlerts().length, 1, 'rejected response must not store any row');
    assert.equal(batches.length, 1, 'rejected response must not notify');
    assert.equal(errors.length, 1, 'malformed response must be an error, not an ordinary empty sample');
    assert.ok(errors[0]!.includes('Invalid Wazuh polling response'), errors.join('\n'));
    assert.ok(!errors.join('\n').includes('PAYLOAD-CANARY'), 'validation diagnostics must not echo untrusted fields');
    await intervals[0]!();
    assert.equal(cursor(2), source(10).timestamp, 'failed response must keep the committed cursor');
    assert.deepEqual(getRecentAlerts().map(item => item.timestamp), [source(13).timestamp, source(10).timestamp]);
    assert.equal(getRecentAlerts()[0]!.id, 2, 'invalid batch must not reserve IDs');
    assert.equal(scoreCalls, 2, 'later successful tick must recover after rejection');
    assert.equal(batches.length, 2);
  }
} finally {
  globalThis.fetch = originalFetch;
  globalThis.setInterval = originalInterval;
  console.error = originalError;
  rmSync(root, { recursive: true, force: true });
}
