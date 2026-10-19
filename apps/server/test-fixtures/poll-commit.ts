import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WazuhAlert } from '../src/types';
import { getScoringBackend, registerScoringBackend } from '../src/scorer';

const scenario = process.argv[2];
const root = mkdtempSync(join(tmpdir(), 'specter-poll-commit-'));
const file = join(root, 'alerts.jsonl');
delete process.env.WAZUH_CA_FILE;
delete process.env.WAZUH_INSECURE_TLS;
process.env.WAZUH_DASHBOARD_URL = 'https://wazuh.poll-commit.invalid';
process.env.WAZUH_DASHBOARD_USER = 'synthetic-reader';
process.env.WAZUH_DASHBOARD_PASSWORD = 'synthetic-not-a-secret';
process.env.WAZUH_ALERTS_PATH = file;
process.env.WAZUH_POLL_INTERVAL = '30000';

function alert(second: number, label = `poll-${second}`): WazuhAlert {
  return {
    timestamp: new Date(Date.UTC(2026, 9, 19, 12, 0, second)).toISOString(),
    rule: { id: 'synthetic-rule', level: 7, description: label },
    agent: { id: '001', name: 'synthetic-agent' },
  };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(yes => { resolve = yes; });
  return { promise, resolve };
}
const held = deferred();
const late = deferred();
const originalInterval = globalThis.setInterval;
const originalFetch = globalThis.fetch;
const intervals: (() => Promise<void>)[] = [];
globalThis.setInterval = ((callback: () => Promise<void>) => {
  intervals.push(callback);
  return intervals.length as unknown as ReturnType<typeof setInterval>;
}) as typeof setInterval;
const tick = () => intervals[0]!();
const settle = () => new Promise<void>(resolve => setImmediate(resolve));
async function waitFor(predicate: () => boolean) {
  const deadline = Date.now() + 2000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, 'fixture did not reach its expected state');
    await Bun.sleep(5);
  }
}

let dataset = [alert(10)];
const queries: any[] = [];
function cursor(index: number): string | undefined {
  const clauses = queries[index].query.bool.must as any[];
  return clauses.find(clause => clause.range)?.range.timestamp.gt;
}
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  assert.equal(url.origin, 'https://wazuh.poll-commit.invalid');
  assert.equal(url.pathname, '/api/console/proxy');
  assert.equal(url.searchParams.get('path'), 'wazuh-alerts-*/_search');
  const query = JSON.parse(String(init?.body));
  assert.equal(query.size, 100);
  assert.deepEqual(query.sort, [{ timestamp: { order: 'desc' } }]);
  queries.push(query);
  const gt = cursor(queries.length - 1);
  const hits = dataset.filter(item => !gt || item.timestamp > gt)
    .toSorted((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, 100).map(_source => ({ _source }));
  return Response.json({ timed_out: false, _shards: { total: 1, successful: 1, failed: 0 }, hits: { hits } });
}) as typeof fetch;

let scoreHook: ((item: WazuhAlert) => Promise<void>) | undefined;
const backend = getScoringBackend();
registerScoringBackend({
  name: 'controlled-real-scorer',
  async score(item, context) {
    if (scoreHook) await scoreHook(item);
    return backend.score(item, context);
  },
});
let exitCode = 0;
try {
  const { addAlerts, getRecentAlerts, startAlertIngestion } = await import('../src/alert-ingest');
  const batches: WazuhAlert[][] = [];
  let notifyHook: ((items: WazuhAlert[]) => void) | undefined;
  let reentered: Promise<void> | undefined;
  const stored = () => getRecentAlerts(500);
  const descriptions = () => stored().map(item => item.rule.description);
  if (scenario === 'file-interleave') writeFileSync(file, JSON.stringify(alert(0, 'existing-file')) + '\n');
  if (scenario === 'initial-score-retry') scoreHook = async () => { throw new Error('synthetic scoring rejection'); };
  if (scenario === 'retention-order') {
    await addAlerts(Array.from({ length: 450 }, (_, i) => alert(-450 + i, `seed-${i}`)));
    dataset = Array.from({ length: 100 }, (_, i) => alert(1 + i));
  }
  startAlertIngestion(items => {
    batches.push(items);
    if (notifyHook) notifyHook(items);
  });
  await settle();
  assert.equal(intervals.length, 1);
  assert.equal(queries.length, 1);
  assert.equal(cursor(0), undefined);

  if (scenario === 'initial-score-retry') {
    assert.equal(stored().length, 0);
    scoreHook = undefined;
    await tick();
    assert.equal(cursor(1), undefined, 'failed initial scoring must not establish a cursor');
    assert.deepEqual(descriptions(), ['poll-10']);
    await tick();
    assert.equal(cursor(2), alert(10).timestamp);
    assert.equal(stored().length, 1, 'successful retry is stored once');
  } else if (scenario === 'committed-score-retry' || scenario === 'partial-scoring') {
    dataset = [alert(11), alert(12), alert(13)];
    let completed = 0;
    scoreHook = async item => {
      if (scenario === 'partial-scoring' && item.rule.description === 'poll-13') await late.promise;
      if (item.rule.description === 'poll-12') throw new Error('synthetic middle-item rejection');
      completed++;
    };
    await tick();
    assert.equal(cursor(1), alert(10).timestamp);
    assert.deepEqual(descriptions(), ['poll-10'], 'one rejected score must prevent the entire batch store');
    late.resolve();
    await settle();
    assert.equal(completed, 2);
    assert.deepEqual(descriptions(), ['poll-10'], 'late scoring settlement must not store a rejected batch');
    scoreHook = undefined;
    await tick();
    assert.equal(cursor(2), alert(10).timestamp, 'failed batch must retain the previously committed cursor');
    assert.deepEqual(descriptions(), ['poll-13', 'poll-12', 'poll-11', 'poll-10']);
    await tick();
    assert.equal(cursor(3), alert(13).timestamp);
    assert.equal(stored().length, 4);
  } else if (scenario === 'subscriber-error' || scenario === 'notification-reentry') {
    dataset = [alert(11), alert(12)];
    notifyHook = items => {
      assert.equal(stored().length, 3, 'whole batch must be stored before notification');
      assert.deepEqual(items.map(item => item.rule.description), ['poll-11', 'poll-12']);
      reentered = tick();
      if (scenario === 'subscriber-error') throw new Error('synthetic notification rejection');
    };
    await tick();
    await reentered;
    assert.equal(queries.length, 2, 'subscriber reentry must not start a poll while the guard is held');
    notifyHook = undefined;
    await tick();
    assert.equal(cursor(2), alert(12).timestamp, 'stored batch must commit even if its subscriber throws');
    assert.equal(stored().length, 3, 'committed batch must not replay after notification failure');
    assert.equal(batches.length, 2);
    assert.deepEqual(batches[1]!.map(item => item.id), [2, 3], 'each stored poll row must reserve one ID');
    const next = await addAlerts([alert(90, 'next-public')]);
    assert.equal(next[0]!.id, 4, 'poll stages must not reserve IDs a second time');
    assert.equal(stored().length, 4);
    assert.equal(batches.length, 3, 'each committed batch must notify once');
  } else if (scenario === 'public-interleave' || scenario === 'file-interleave') {
    dataset = [alert(11)];
    scoreHook = async item => { if (item.rule.description === 'poll-11') await held.promise; };
    const pending = tick();
    await settle();
    if (scenario === 'public-interleave') {
      const returned = await addAlerts([alert(90, 'http-like-public')]);
      assert.equal(returned[0]!.rule.description, 'http-like-public');
      notifyHook = () => { throw new Error('synthetic public notification rejection'); };
      await assert.rejects(addAlerts([alert(91, 'public-postcommit-error')]), /synthetic public notification rejection/);
      assert.ok(descriptions().includes('public-postcommit-error'), 'public callback rejection remains post-commit');
      notifyHook = undefined;
    } else {
      appendFileSync(file, JSON.stringify(alert(90, 'file-new')) + '\n');
      await waitFor(() => descriptions().includes('file-new'));
      assert.ok(!descriptions().includes('existing-file'), 'watching must preserve the existing tail-only behavior');
    }
    await tick();
    assert.equal(queries.length, 2, 'unrelated ingestion must not release the active polling guard');
    held.resolve();
    await pending;
    scoreHook = undefined;
    dataset = [alert(12)];
    await tick();
    assert.equal(cursor(2), alert(11).timestamp, 'HTTP/file timestamps must not advance the poll cursor');
    assert.ok(descriptions().includes('poll-12'));
  } else if (scenario === 'retention-order') {
    assert.equal(stored().length, 500);
    assert.deepEqual(descriptions().slice(0, 100), dataset.toReversed().map(item => item.rule.description));
    assert.equal(stored().at(-1)!.rule.description, 'seed-50', 'normal eviction retains the final 500 records');
    assert.deepEqual(batches[0]!.map(item => item.timestamp), dataset.map(item => item.timestamp));
    dataset = [alert(101), alert(102)];
    await tick();
    assert.equal(cursor(1), alert(100).timestamp);
    assert.equal(stored().length, 500);
    await tick();
    assert.equal(cursor(2), alert(102).timestamp, 'successive committed batches advance to their newest timestamp');
    assert.equal(stored().length, 500);
  } else if (scenario === 'empty-retains-cursor') {
    dataset = [];
    await tick();
    assert.equal(cursor(1), alert(10).timestamp);
    dataset = [alert(11)];
    await tick();
    assert.equal(cursor(2), alert(10).timestamp, 'empty response must preserve the committed cursor');
    assert.deepEqual(descriptions(), ['poll-11', 'poll-10']);
  } else throw new Error('unknown scenario');
} catch (error) {
  console.error(error);
  exitCode = 1;
} finally {
  held.resolve();
  late.resolve();
  globalThis.fetch = originalFetch;
  globalThis.setInterval = originalInterval;
  rmSync(root, { recursive: true, force: true });
}
// The real file-watcher scenario is confined to this owned disposable child.
process.exit(exitCode);
