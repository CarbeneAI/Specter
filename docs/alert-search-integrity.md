# Direct alert search integrity

The direct Wazuh search in `apps/server/src/pai-client.ts` distinguishes a
complete empty search from an unsuccessful search. HTTP 200 alone does not
establish that OpenSearch completed the query or returned a valid result.
The same function serves the `/alerts/search` route and the model's historical
alert-search tool.

A successful response must contain:

- `timed_out: false`, no top-level error, and no early termination.
- A positive, safe integer shard total, every shard successful, and zero failed
  shards. Optional skipped counts and failure lists must not contradict this.
- An array of hit objects with object `_source` records.
- A nonnegative safe integer total, either the legacy numeric form or an object
  with `relation: "eq"`. Lower-bound counts and missing totals are errors.
- A sample no larger than the exact total or requested size. A positive total
  requires at least one returned hit; a zero total requires an empty sample.

Missing or null optional alert fields remain supported. Non-null `full_log`
values must be strings and non-null MITRE ID lists must be arrays of strings so projection
and tool-result formatting can complete. This is a response integrity check,
not validation of every Wazuh document field.

Failures retain the existing `{ results: [], total: 0, error }` response shape.
The model-facing formatter checks `error` first and emits `Search error:` rather
than `No alerts found`. API consumers must inspect `error`; the numeric zero in
an error response is not evidence that no matching alerts exist. Only a
validated exact zero result receives the normal absence message.

## Exact counts and bounded samples

Search requests now set `track_total_hits: true` because the formatter reports
an exact total. [OpenSearch documents that counting every match can slow broad
searches](https://docs.opensearch.org/latest/api-reference/search-apis/search/#track-total-hits).
Use focused filters and time ranges when investigating large indexes. The
returned sample still defaults to 20 hits and is capped at 100. A valid sample
can be smaller than the exact total; the formatter reports both numbers.
This does not add pagination or promise that every matching alert was returned.
It does not change TLS configuration, polling, remote history scripts, or the
query input contract.

## Checks for contributors and coding agents

Use Bun 1.3.14. From the repository root:

```bash
cd apps/server
bun install --frozen-lockfile --no-env-file
bun test --no-env-file src/alert-search.test.ts
bun test --no-env-file
bun run --no-env-file typecheck
```

The 42 direct-search fixtures replace only `fetch` and exercise the production
search function and formatter with synthetic responses. They cover exact empty
and positive results, legacy totals, malformed HTTP 200 documents, timeouts,
early termination, shard failures, lower-bound counts, contradictory samples,
source shapes, and HTTP/JSON/transport failures. They do not contact Wazuh,
a model provider, SSH, or another external service.

On upstream baseline `d38244b` plus this contribution, the complete server suite
passes 123 tests, including existing loopback HTTP fixtures and temporary SQLite
databases. The integration fixture points `WAZUH_ALERTS_PATH` at a nonexistent
file in its disposable directory and restores the caller environment afterward. The server lockfile is identical
to the other server reliability contributions. CI runs the same tests and
TypeScript check on Ubuntu and macOS. These fixtures do not validate a live
OpenSearch deployment or establish readiness for public hosting.
