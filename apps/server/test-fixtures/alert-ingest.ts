import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WazuhAlert } from '../src/types';
import { getScoringBackend, registerScoringBackend } from '../src/scorer';

const directory = mkdtempSync(join(tmpdir(), 'specter-alert-ids-'));
const file = join(directory, 'alerts.jsonl');
process.env.WAZUH_DASHBOARD_URL = 'https://wazuh.invalid.test';
process.env.WAZUH_DASHBOARD_PASSWORD = 'fixture-only';
process.env.WAZUH_POLL_INTERVAL = '60000';
process.env.WAZUH_ALERTS_PATH = file;

// No fixture may reach a real Wazuh, model provider, or other external service.
globalThis.fetch = (async () => { throw new Error('Unexpected outbound request'); }) as unknown as typeof fetch;

function alert(label: string, id = 1): WazuhAlert {
  return {
    id,
    timestamp: new Date().toISOString(),
    rule: { level: 5, id: '100', description: label },
    agent: { id: '001', name: 'fixture' },
  };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 3000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('Fixture did not reach the expected state');
    await Bun.sleep(10);
  }
}

let exitCode = 0;
try {
  const { addAlerts, getRecentAlerts, startAlertIngestion } = await import('../src/alert-ingest');
  const scenario = process.argv[2];
  if (scenario === 'retention') {
    const seen = new Set<number>();
    for (let batch = 0; batch < 4; batch++) {
      const input = Array.from({ length: 400 }, (_, index) => alert(`${batch}:${index}`));
      const returned = await addAlerts(input);
      for (const item of returned) {
        assert.equal(Number.isSafeInteger(item.id), true);
        assert.equal(seen.has(item.id!), false, 'retention must not recycle a dismissed alert ID');
        seen.add(item.id!);
      }
      assert.equal(input.every(item => item.id === 1 && item.verdict === undefined), true);
      const stored = getRecentAlerts(500);
      assert.equal(stored.length, Math.min((batch + 1) * 400, 500));
      assert.equal(new Set(stored.map(item => item.id)).size, stored.length);
      assert.deepEqual(stored.slice(0, 400), returned.toReversed());
    }
    assert.equal(seen.size, 1600);
    assert.deepEqual(await addAlerts([]), []);
  } else if (scenario === 'concurrent') {
    const backend = getScoringBackend();
    const release: Array<() => void> = [];
    registerScoringBackend({
      name: 'deferred-fixture',
      async score(item, context) {
        await new Promise<void>(resolve => release.push(resolve));
        return backend.score(item, context);
      },
    });
    const first = addAlerts([alert('first')]);
    const second = addAlerts([alert('second')]);
    assert.equal(release.length, 2);
    release[1]!();
    const secondResult = await second;
    release[0]!();
    const firstResult = await first;
    assert.notEqual(firstResult[0]!.id, secondResult[0]!.id, 'overlapping scoring must reserve distinct IDs');
    assert.ok(firstResult[0]!.id! < secondResult[0]!.id!);
    assert.deepEqual(getRecentAlerts(2), [...firstResult, ...secondResult]);
  } else if (scenario === 'mixed-sources') {
    // Populate the buffer first so every source must allocate beyond the cap.
    const initial = await addAlerts(Array.from({ length: 500 }, (_, index) => alert(`initial:${index}`)));
    const backend = getScoringBackend();
    const release: Array<() => void> = [];
    registerScoringBackend({
      name: 'mixed-deferred-fixture',
      async score(item, context) {
        await new Promise<void>(resolve => release.push(resolve));
        return backend.score(item, context);
      },
    });
    writeFileSync(file, JSON.stringify(alert('existing file content')) + '\n');
    globalThis.fetch = (async (input: string | URL | Request) => {
      assert.match(String(input), /^https:\/\/wazuh\.invalid\.test\/api\/console\/proxy\?/);
      return Response.json({
        timed_out: false,
        _shards: { total: 1, successful: 1, failed: 0 },
        hits: { hits: [{ _source: alert('indexer') }] },
      });
    }) as typeof fetch;
    const broadcast: WazuhAlert[] = [];
    startAlertIngestion(items => broadcast.push(...items));
    await waitFor(() => release.length === 1);
    appendFileSync(file, JSON.stringify(alert('file', 501)) + '\n');
    await waitFor(() => release.length === 2);
    const http = addAlerts([alert('http', 501)]);
    assert.equal(release.length, 3);
    // Complete sources in the opposite order to their arrival.
    release[2]!();
    const httpResult = await http;
    release[1]!();
    await waitFor(() => broadcast.length === 2);
    release[0]!();
    await waitFor(() => broadcast.length === 3);
    const allIds = [...initial, ...broadcast].map(item => item.id);
    assert.equal(new Set(allIds).size, 503, 'polling, file, and HTTP ingestion must share one ID sequence');
    assert.deepEqual(broadcast.find(item => item.rule.description === 'http'), httpResult[0]);
    assert.deepEqual(getRecentAlerts(3), broadcast.toReversed());
    assert.equal(getRecentAlerts(500).length, 500);
  } else if (scenario === 'failed-scoring') {
    const backend = getScoringBackend();
    let reservedId: number | undefined;
    registerScoringBackend({
      name: 'failing-fixture',
      async score(item) {
        reservedId = item.id;
        throw new Error('Fixture scoring failure');
      },
    });
    await assert.rejects(addAlerts([alert('fails')]), /Fixture scoring failure/);
    assert.deepEqual(getRecentAlerts(), []);
    registerScoringBackend(backend);
    const result = await addAlerts([alert('succeeds')]);
    assert.ok(result[0]!.id! > reservedId!, 'a failed reservation must not be reused');
  } else {
    throw new Error(`Unknown fixture: ${scenario}`);
  }
} catch (error) {
  console.error(error);
  exitCode = 1;
} finally {
  rmSync(directory, { recursive: true, force: true });
}

// Poll timers and file watchers are intentionally confined to this disposable process.
process.exit(exitCode);
