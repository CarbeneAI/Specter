/** Offline direct-search fixtures. Only fetch is replaced; parsing and formatting stay real. */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, mock, spyOn } from 'bun:test';

let searchWazuhAlerts: typeof import('./pai-client').searchWazuhAlerts;
let formatSearchResults: typeof import('./pai-client').formatSearchResults;
let response: unknown;
const envKeys = ['WAZUH_DASHBOARD_URL', 'WAZUH_DASHBOARD_USER', 'WAZUH_DASHBOARD_PASSWORD'] as const;
const original = envKeys.map(key => process.env[key]);

function complete(total: unknown = { value: 0, relation: 'eq' }, hits: unknown[] = []): any {
  return {
    timed_out: false,
    _shards: { total: 2, successful: 2, skipped: 0, failed: 0 },
    hits: { total, hits },
  };
}

function hit(): any {
  return { _source: {
    timestamp: '2026-10-19T00:00:00Z',
    rule: { id: '123', level: 7, description: 'Synthetic alert', mitre: { id: ['T1000'] } },
    agent: { name: 'fixture-agent' },
    data: { src_ip: '192.0.2.1', dest_ip: '192.0.2.2', dest_port: 443, proto: 'TCP',
      alert: { signature_id: 100, signature: 'Fixture signature' } },
    full_log: 'x'.repeat(350),
  } };
}

beforeAll(async () => {
  process.env.WAZUH_DASHBOARD_URL = 'https://wazuh.invalid.test';
  process.env.WAZUH_DASHBOARD_USER = 'fixture-user';
  process.env.WAZUH_DASHBOARD_PASSWORD = 'fixture-password';
  ({ searchWazuhAlerts, formatSearchResults } = await import('./pai-client'));
});

afterAll(() => {
  envKeys.forEach((key, index) => {
    if (original[index] === undefined) delete process.env[key];
    else process.env[key] = original[index];
  });
});

beforeEach(() => {
  response = complete();
  spyOn(globalThis, 'fetch').mockImplementation(Object.assign(
    async () => Response.json(response),
    { preconnect: () => { throw new Error('Unexpected preconnect in an offline fixture'); } },
  ));
  spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => mock.restore());

describe('direct Wazuh alert-search response integrity', () => {
  it('reports absence only for a complete exact zero response', async () => {
    const result = await searchWazuhAlerts({});
    expect(result).toEqual({ results: [], total: 0 });
    expect(formatSearchResults(result)).toBe('No alerts found matching the search criteria.');
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, options] = (fetch as any).mock.calls[0];
    expect(new URL(url).pathname).toBe('/api/console/proxy');
    expect(new URL(url).searchParams.get('path')).toBe('wazuh-alerts-*/_search');
    expect(JSON.parse(options.body)).toMatchObject({ size: 20, track_total_hits: true });
  });

  it('accepts legacy integer totals including zero', async () => {
    for (const total of [0, 25]) {
      response = complete(total, total ? [hit()] : []);
      const result = await searchWazuhAlerts({});
      expect(result.error).toBeUndefined();
      expect(result.total).toBe(total);
    }
  });

  it('preserves exact total and mapped fields for a smaller positive sample', async () => {
    response = complete({ value: 25, relation: 'eq' }, [hit()]);
    const result = await searchWazuhAlerts({ limit: 2 });
    expect(result.error).toBeUndefined();
    expect(result.total).toBe(25);
    expect(result.results).toHaveLength(1);
    expect(result.results[0]).toMatchObject({ rule_id: '123', rule_level: 7, agent_name: 'fixture-agent',
      src_ip: '192.0.2.1', dest_ip: '192.0.2.2', dest_port: 443, protocol: 'TCP', mitre_ids: ['T1000'] });
    expect(result.results[0].full_log).toHaveLength(300);
    expect(formatSearchResults(result)).toContain('Found 25 total alerts (showing 1)');
    expect(formatSearchResults(result)).toContain('MITRE: T1000');
  });

  it('retains the 100-hit request cap and allows absent optional metadata', async () => {
    response = complete(1, [{ _source: {} }]);
    const result = await searchWazuhAlerts({ limit: 500 });
    expect(result.error).toBeUndefined();
    expect(result.total).toBe(1);
    const [, options] = (fetch as any).mock.calls[0];
    expect(JSON.parse(options.body)).toMatchObject({ size: 100, track_total_hits: true });
  });

  it('allows older complete responses without optional skipped/failures fields', async () => {
    response = { ...complete(), _shards: { total: 1, successful: 1, failed: 0 }, terminated_early: false };
    expect((await searchWazuhAlerts({})).error).toBeUndefined();
  });

  const invalid: [string, () => unknown][] = [
    ['HTTP 200 error documents', () => ({ ...complete(), error: { reason: 'fixture error' } })],
    ['missing envelopes', () => ({})],
    ['null documents', () => null],
    ['array documents', () => []],
    ['timed-out searches', () => ({ ...complete(), timed_out: true })],
    ['missing completion flags', () => ({ ...complete(), timed_out: undefined })],
    ['nonboolean completion flags', () => ({ ...complete(), timed_out: 'false' })],
    ['early termination', () => ({ ...complete(), terminated_early: true })],
    ['missing shard metadata', () => ({ ...complete(), _shards: undefined })],
    ['zero searched shards', () => ({ ...complete(), _shards: { total: 0, successful: 0, failed: 0 } })],
    ['failed shards', () => ({ ...complete(), _shards: { total: 2, successful: 1, failed: 1 } })],
    ['incomplete successful shard accounting', () => ({ ...complete(), _shards: { total: 2, successful: 1, failed: 0 } })],
    ['fractional shard counts', () => ({ ...complete(), _shards: { total: 1.5, successful: 1.5, failed: 0 } })],
    ['contradictory shard failures', () => ({ ...complete(), _shards: { total: 2, successful: 2, failed: 0, failures: [{}] } })],
    ['invalid optional skipped counts', () => ({ ...complete(), _shards: { total: 2, successful: 2, failed: 0, skipped: 3 } })],
    ['missing hit records', () => ({ ...complete(), hits: undefined })],
    ['nonarray hits', () => ({ ...complete(), hits: { total: 0, hits: {} } })],
    ['missing totals', () => ({ ...complete(), hits: { hits: [] } })],
    ['negative totals', () => complete(-1)],
    ['fractional totals', () => complete(0.5)],
    ['unsafe integer totals', () => complete(Number.MAX_SAFE_INTEGER + 1)],
    ['string totals', () => complete('0')],
    ['lower-bound totals', () => complete({ value: 0, relation: 'gte' })],
    ['missing total relations', () => complete({ value: 0 })],
    ['invalid object total values', () => complete({ value: -1, relation: 'eq' })],
    ['positive totals without evidence', () => complete(1)],
    ['zero totals with evidence', () => complete(0, [hit()])],
    ['samples larger than totals', () => complete(1, [hit(), hit()])],
    ['samples larger than requested size', () => complete(3, [hit(), hit(), hit()])],
    ['null hit items', () => complete(1, [null])],
    ['missing source records', () => complete(1, [{}])],
    ['null source records', () => complete(1, [{ _source: null }])],
    ['array source records', () => complete(1, [{ _source: [] }])],
    ['string source records', () => complete(1, [{ _source: 'not an alert' }])],
    ['invalid full-log types', () => complete(1, [{ _source: { full_log: 42 } }])],
    ['invalid MITRE identifiers', () => complete(1, [{ _source: { rule: { mitre: { id: 'T1000' } } } }])],
  ];

  for (const [name, build] of invalid) {
    it(`returns an error instead of absence for ${name}`, async () => {
      response = build();
      const result = await searchWazuhAlerts({ limit: 2 });
      expect(result.error).toBeTruthy();
      expect(result.results).toEqual([]);
      expect(result.total).toBe(0);
      expect(formatSearchResults(result)).toStartWith('Search error:');
      expect(formatSearchResults(result)).not.toContain('No alerts found');
    });
  }

  it('preserves the error path for HTTP errors, invalid JSON, and transport failures', async () => {
    for (const failure of [new Response('fixture unavailable', { status: 503 }), new Response('{')]) {
      spyOn(globalThis, 'fetch').mockResolvedValueOnce(failure);
      const result = await searchWazuhAlerts({});
      expect(result.error).toBeTruthy();
      expect(formatSearchResults(result)).toStartWith('Search error:');
    }
    spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('fixture connection failure'));
    const result = await searchWazuhAlerts({});
    expect(result.error).toContain('fixture connection failure');
    expect(formatSearchResults(result)).not.toContain('No alerts found');
  });
});
