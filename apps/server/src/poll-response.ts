/** Consumed-field contract for the poll's unfiltered synchronous _search response.
 * Validate the whole descending sample before reserving IDs or scoring any row.
 * This is not pagination, a full Wazuh schema, or an exact-total requirement.
 */
type RecordValue = Record<string, unknown>;
interface PollHit { _source: RecordValue & { timestamp: string } }
const record = (value: unknown): value is RecordValue => value !== null && typeof value === 'object' && !Array.isArray(value);
const count = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const optionalText = (value: unknown) => value == null || typeof value === 'string';
const optionalPort = (value: unknown) => optionalText(value) || (typeof value === 'number' && Number.isFinite(value));
const optionalStrings = (value: unknown) => value == null || (Array.isArray(value) && value.every(item => typeof item === 'string'));
const fields = (value: RecordValue, names: string[], valid: (item: unknown) => boolean) => names.every(name => valid(value[name]));
const optionalRecord = (value: unknown, valid: (item: RecordValue) => boolean) => value == null || (record(value) && valid(value));

function sourceValid(value: unknown): value is PollHit['_source'] {
  if (!record(value) || typeof value.timestamp !== 'string' || !value.timestamp.trim() || !Number.isFinite(Date.parse(value.timestamp))) return false;
  if (!record(value.rule)) return false;
  const rule = value.rule;
  // Wazuh levels may be JSON numbers or integer strings; do not silently parse a prefix.
  if (!(count(rule.level) || (typeof rule.level === 'string' && /^\d+$/.test(rule.level) && count(Number(rule.level))))) return false;
  if (!fields(rule, ['id', 'description'], optionalText)
    || !fields(rule, ['groups', 'pci_dss', 'gdpr', 'hipaa', 'nist_800_53'], optionalStrings)
    || !optionalRecord(rule.mitre, mitre => fields(mitre, ['id', 'tactic', 'technique'], optionalStrings))) return false;
  return optionalRecord(value.agent, agent => fields(agent, ['id', 'name', 'ip'], optionalText))
    && optionalRecord(value.manager, manager => optionalText(manager.name))
    && optionalRecord(value.decoder, decoder => optionalText(decoder.name))
    && optionalRecord(value.data, data => fields(data, ['src_ip', 'dest_ip', 'proto'], optionalText) && optionalPort(data.dest_port))
    && fields(value, ['full_log', 'location', 'srcip', 'dstip', 'protocol'], optionalText)
    && optionalPort(value.dstport);
}

function invalid(reason: string): never {
  // Callers pass fixed literals only. Do not include upstream payloads or credentials.
  throw new Error(`Invalid Wazuh polling response: ${reason}`);
}

function validate(body: unknown, previousCursor: string | null): PollHit[] {
  if (!record(body) || 'error' in body || body.timed_out !== false
    || (body.terminated_early !== undefined && body.terminated_early !== false)) invalid('incomplete search');
  const shards = body._shards;
  if (!record(shards) || !count(shards.total) || !count(shards.successful) || !count(shards.failed)
    || shards.successful !== shards.total || shards.failed !== 0
    || (shards.skipped !== undefined && (!count(shards.skipped) || shards.skipped > shards.successful))
    || (shards.failures !== undefined && (!Array.isArray(shards.failures) || shards.failures.length !== 0))) invalid('incomplete shards');
  // Successful already includes skipped shards; adding skipped again rejects valid searches.
  if (!record(body.hits) || !Array.isArray(body.hits.hits) || body.hits.hits.length > 100) invalid('invalid hit sample');
  const hits = body.hits.hits;
  let total: number | undefined;
  let exact = false;
  if (body.hits.total !== undefined) {
    if (count(body.hits.total)) {
      total = body.hits.total;
      exact = true;
    } else if (record(body.hits.total) && count(body.hits.total.value)
      && (body.hits.total.relation === 'eq' || body.hits.total.relation === 'gte')) {
      total = body.hits.total.value;
      exact = body.hits.total.relation === 'eq';
    } else invalid('invalid hit total');
    // A lower bound is not an upper bound: the returned sample may exceed it.
    if ((exact && hits.length > total) || (total > 0 && hits.length === 0)) invalid('inconsistent hit total');
  }
  if (shards.total === 0 && (hits.length !== 0 || (total !== undefined && total !== 0))) invalid('hits without searched shards');
  let previousTime = Infinity;
  const cursorTime = previousCursor === null ? -Infinity : Date.parse(previousCursor);
  for (const hit of hits) {
    if (!record(hit) || !sourceValid(hit._source)) invalid('invalid alert fields');
    const time = Date.parse(hit._source.timestamp);
    // These checks rely on this poll's descending timestamp sort, no offset, and strict gt.
    if (time > previousTime || time <= cursorTime) invalid('invalid timestamp order');
    previousTime = time;
  }
  return hits as PollHit[];
}

export async function readWazuhPollResponse(response: Response, previousCursor: string | null): Promise<PollHit[]> {
  let body: unknown;
  try { body = await response.json(); }
  catch { invalid('invalid JSON'); }
  return validate(body, previousCursor);
}
