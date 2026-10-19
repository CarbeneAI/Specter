// Synthetic wire responses shared by the subprocess fixture and its test inventory.
type Body = Record<string, any>;
export function source(second: number, description = `poll-${second}`): Body {
  return {
    timestamp: new Date(Date.UTC(2026, 9, 19, 12, 0, second)).toISOString(),
    rule: { id: 'synthetic-rule', level: 7, description },
    agent: { id: '001', name: 'synthetic-agent' },
  };
}
export function complete(rows: Body[] = [source(12), source(11)]): Body {
  return {
    timed_out: false,
    _shards: { total: 2, successful: 2, failed: 0 },
    hits: { total: { value: rows.length, relation: 'eq' }, hits: rows.map(_source => ({ _source })) },
  };
}
type Case = { name: string; accept: boolean; body: () => unknown; invalidJson?: boolean };
const bad = (name: string, change: (body: Body) => void): Case => ({
  name, accept: false, body: () => { const body = complete(); change(body); return body; },
});
const good = (name: string, change: (body: Body) => void): Case => ({
  name, accept: true, body: () => { const body = complete(); change(body); return body; },
});
export const cases: Case[] = [
  { name: 'null-envelope', accept: false, body: () => null },
  { name: 'array-envelope', accept: false, body: () => [] },
  { name: 'missing-envelope', accept: false, body: () => ({}) },
  { name: 'invalid-json', accept: false, invalidJson: true, body: () => null },
  bad('error-envelope', b => { b.error = { reason: 'PAYLOAD-CANARY' }; }),
  bad('null-error', b => { b.error = null; }),
  bad('timeout', b => { b.timed_out = true; }),
  bad('missing-timeout', b => { delete b.timed_out; }),
  bad('string-timeout', b => { b.timed_out = 'false'; }),
  bad('early-termination', b => { b.terminated_early = true; }),
  bad('invalid-termination', b => { b.terminated_early = 'false'; }),
  bad('missing-shards', b => { delete b._shards; }),
  bad('null-shards', b => { b._shards = null; }),
  bad('array-shards', b => { b._shards = []; }),
  bad('missing-shard-count', b => { delete b._shards.total; }),
  bad('negative-shards', b => { b._shards.total = -1; }),
  bad('fractional-shards', b => { b._shards.total = 2.5; }),
  bad('unsafe-shards', b => { b._shards.total = Number.MAX_SAFE_INTEGER + 1; }),
  bad('string-shards', b => { b._shards.total = '2'; }),
  bad('failed-shard', b => { b._shards.failed = 1; b._shards.successful = 1; }),
  bad('missing-failed-count', b => { delete b._shards.failed; }),
  bad('negative-failed-count', b => { b._shards.failed = -1; }),
  bad('incomplete-shards', b => { b._shards.successful = 1; }),
  bad('missing-successful-count', b => { delete b._shards.successful; }),
  bad('contradictory-failures', b => { b._shards.failures = [{ reason: 'PAYLOAD-CANARY' }]; }),
  bad('malformed-failures', b => { b._shards.failures = {}; }),
  bad('negative-skipped', b => { b._shards.skipped = -1; }),
  bad('excessive-skipped', b => { b._shards.skipped = 3; }),
  bad('zero-shards-with-hits', b => { b._shards = { total: 0, successful: 0, failed: 0 }; }),
  bad('zero-shards-positive-total', b => {
    b._shards = { total: 0, successful: 0, failed: 0 };
    b.hits = { total: { value: 1, relation: 'gte' }, hits: [] };
  }),
  bad('missing-hits-envelope', b => { delete b.hits; }),
  bad('null-hits-envelope', b => { b.hits = null; }),
  bad('array-hits-envelope', b => { b.hits = []; }),
  bad('missing-hit-array', b => { delete b.hits.hits; }),
  bad('null-hit-array', b => { b.hits.hits = null; }),
  bad('object-hit-array', b => { b.hits.hits = {}; }),
  bad('oversized-sample', b => {
    b.hits.hits = Array.from({ length: 101 }, (_, i) => ({ _source: source(120 - i) }));
    b.hits.total.value = 101;
  }),
  bad('null-hit-after-valid', b => { b.hits.hits[1] = null; }),
  bad('array-hit-after-valid', b => { b.hits.hits[1] = []; }),
  bad('null-source-after-valid', b => { b.hits.hits[1]._source = null; }),
  bad('array-source-after-valid', b => { b.hits.hits[1]._source = []; }),
  bad('missing-source-after-valid', b => { delete b.hits.hits[1]._source; }),
  bad('null-total', b => { b.hits.total = null; }),
  bad('string-total', b => { b.hits.total = '2'; }),
  bad('negative-total', b => { b.hits.total = -1; }),
  bad('fractional-total', b => { b.hits.total = 2.5; }),
  bad('unsafe-total', b => { b.hits.total = Number.MAX_SAFE_INTEGER + 1; }),
  bad('missing-total-value', b => { b.hits.total = { relation: 'eq' }; }),
  bad('invalid-total-relation', b => { b.hits.total.relation = 'PAYLOAD-CANARY'; }),
  bad('exact-zero-with-hits', b => { b.hits.total = 0; }),
  bad('exact-total-below-sample', b => { b.hits.total.value = 1; }),
  bad('positive-exact-empty', b => { b.hits.hits = []; }),
  bad('positive-lower-bound-empty', b => { b.hits = { total: { value: 1, relation: 'gte' }, hits: [] }; }),
  bad('missing-timestamp', b => { delete b.hits.hits[1]._source.timestamp; }),
  bad('null-timestamp', b => { b.hits.hits[1]._source.timestamp = null; }),
  bad('numeric-timestamp', b => { b.hits.hits[1]._source.timestamp = 1; }),
  bad('invalid-timestamp', b => { b.hits.hits[1]._source.timestamp = 'PAYLOAD-CANARY'; }),
  bad('ascending-sample', b => { b.hits.hits.reverse(); }),
  bad('equal-to-committed-cursor', b => { b.hits.hits[1]._source = source(10); }),
  bad('older-than-committed-cursor', b => { b.hits.hits[1]._source = source(9); }),
  bad('missing-rule', b => { delete b.hits.hits[1]._source.rule; }),
  bad('null-rule', b => { b.hits.hits[1]._source.rule = null; }),
  bad('array-rule', b => { b.hits.hits[1]._source.rule = []; }),
  ...[undefined, null, true, -1, 7.5, '7junk', '', {}].map((value, i) => bad(`invalid-level-${i}`, b => {
    b.hits.hits[1]._source.rule.level = value;
  })),
  ...['id', 'description'].map(field => bad(`invalid-rule-${field}`, b => {
    b.hits.hits[1]._source.rule[field] = { value: 'PAYLOAD-CANARY' };
  })),
  ...['groups', 'pci_dss', 'gdpr', 'hipaa', 'nist_800_53'].map(field => bad(`invalid-rule-${field}`, b => {
    b.hits.hits[1]._source.rule[field] = ['valid', { value: 'PAYLOAD-CANARY' }];
  })),
  bad('invalid-mitre-container', b => { b.hits.hits[1]._source.rule.mitre = []; }),
  ...['id', 'tactic', 'technique'].map(field => bad(`invalid-mitre-${field}`, b => {
    b.hits.hits[1]._source.rule.mitre = { [field]: 'PAYLOAD-CANARY' };
  })),
  ...['agent', 'manager', 'decoder', 'data'].map(field => bad(`invalid-${field}-container`, b => {
    b.hits.hits[1]._source[field] = [];
  })),
  ...['id', 'name', 'ip'].map(field => bad(`invalid-agent-${field}`, b => {
    b.hits.hits[1]._source.agent[field] = { value: 'PAYLOAD-CANARY' };
  })),
  ...['manager', 'decoder'].map(field => bad(`invalid-${field}-name`, b => {
    b.hits.hits[1]._source[field] = { name: [] };
  })),
  ...['full_log', 'location', 'srcip', 'dstip', 'protocol', 'dstport'].map(field => bad(`invalid-source-${field}`, b => {
    b.hits.hits[1]._source[field] = { value: 'PAYLOAD-CANARY' };
  })),
  ...['src_ip', 'dest_ip', 'proto', 'dest_port'].map(field => bad(`invalid-data-${field}`, b => {
    b.hits.hits[1]._source.data = { [field]: { value: 'PAYLOAD-CANARY' } };
  })),
  good('exact-bounded-sample', b => { b.hits.total.value = 200; }),
  good('legacy-integer-total', b => { b.hits.total = 2; }),
  good('lower-bound-total', b => { b.hits.total = { value: 10000, relation: 'gte' }; }),
  good('sample-above-lower-bound', b => { b.hits.total = { value: 1, relation: 'gte' }; }),
  good('nonempty-zero-lower-bound', b => { b.hits.total = { value: 0, relation: 'gte' }; }),
  good('omitted-total', b => { delete b.hits.total; }),
  good('empty-exact-zero', b => { b.hits = { total: { value: 0, relation: 'eq' }, hits: [] }; }),
  good('empty-legacy-zero', b => { b.hits = { total: 0, hits: [] }; }),
  good('empty-lower-bound-zero', b => { b.hits = { total: { value: 0, relation: 'gte' }, hits: [] }; }),
  good('empty-omitted-total', b => { b.hits = { hits: [] }; }),
  good('empty-zero-shards', b => {
    b._shards = { total: 0, successful: 0, failed: 0 };
    b.hits = { total: 0, hits: [] };
  }),
  good('skipped-shards-already-successful', b => {
    b._shards.skipped = 1; b._shards.failures = []; b.terminated_early = false;
  }),
  good('equal-timestamp-distinct-rows', b => { b.hits.hits[1]._source.timestamp = source(12).timestamp; }),
  good('numeric-string-level-and-port', b => {
    b.hits.hits[1]._source.rule.level = '007';
    b.hits.hits[1]._source.data = { dest_port: 443, alert: { arbitrary: [1, null] } };
  }),
  good('optional-absent-fields', b => {
    b.hits.hits[1]._source = { timestamp: source(11).timestamp, rule: { level: 0 } };
  }),
  good('optional-null-fields', b => {
    b.hits.hits[1]._source = {
      timestamp: source(11).timestamp, rule: { level: 0, id: null, description: null, groups: null, mitre: null },
      agent: null, manager: null, decoder: null, data: null, full_log: null,
    };
  }),
  good('optional-metadata-and-extra-fields', b => {
    b.hits.hits[1]._source.rule = {
      level: 16, id: '', description: '', groups: ['x'], pci_dss: [], gdpr: [], hipaa: [], nist_800_53: [],
      mitre: { id: ['T1'], tactic: [], technique: [], unused: {} },
    };
    b.hits.hits[1]._source.data = { src_ip: '192.0.2.1', dest_ip: '198.51.100.1', proto: 'TCP', dest_port: '443', extra: [null, {}] };
    b.extra = { notValidated: true };
  }),
  good('timezone-offset-order', b => {
    b.hits.hits[0]._source.timestamp = '2026-10-19T13:00:12.000+01:00';
    b.hits.hits[1]._source.timestamp = '2026-10-19T12:00:11.000Z';
  }),
];
