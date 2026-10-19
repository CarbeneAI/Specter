# Wazuh polling response validation, concurrency and cursor commits

One scheduled Wazuh poll can run at a time in each Specter process. The poll
acquires its guard synchronously before its first asynchronous operation and
holds it through fetch, response decoding, mapping, scoring, storage, and the
synchronous subscriber callback. A `finally` block releases the guard on settlement,
including empty responses and failures. A repeated `startAlertIngestion` call
does not create a second polling interval or trigger another initial request.
Its existing callback/file-watcher behavior is otherwise unchanged.

The interval is still `WAZUH_POLL_INTERVAL`, defaulting to 30000 milliseconds.
There is still one immediate poll at startup, and the timer is registered once
before it starts. Ticks that arrive during an active poll are skipped, not queued
or replayed. A later scheduled tick may poll after the active operation settles;
there is no catch-up request after settlement. A never-settling fetch, response
reader, or scorer consequently prevents later polls. This change adds
no timeout, cancellation, backoff, or scheduler lifecycle API.

## Accepted polling responses

Before mapping or reserving IDs, the poll validates the entire returned sample.
It requires a synchronous, unfiltered OpenSearch search response through the
Dashboard console proxy: an object without an `error`, `timed_out: false`, and
complete successful `_shards` accounting with no failed shards. These completion
fields are emitted by [OpenSearch 2.19.3's search response implementation](https://github.com/opensearch-project/OpenSearch/blob/2.19.3/server/src/main/java/org/opensearch/action/search/SearchResponse.java#L348),
and the [Dashboard proxy forwards the response body](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/2.19.3/src/plugins/console/server/routes/api/console/proxy/create_handler.ts#L112).
The polling request does not use `filter_path` to remove them. A missing flag or
shard count cannot establish completion and is rejected. This defines the
supported wire contract; it is not live-version compatibility evidence.

`terminated_early` may be absent or false. Optional `skipped` and `failures`
metadata must not contradict success; skipped shards are already included in
successful shards. A zero-shard response is accepted only with an empty sample
and no positive total. It does not establish that an expected index exists.
`hits.hits` must be an array of at most 100 object hits with object `_source`
values. A valid empty array retains the existing cursor without notification.

Unlike direct search's count wording, polling does not require an exact total
or request `track_total_hits: true`. An omitted `hits.total` is accepted. If
provided, it must be a nonnegative safe integer or an object with a safe integer
`value` and `eq` or `gte` relation. An exact total cannot be smaller than its
sample, and a positive total cannot accompany an empty sample for this query.
A lower bound can exceed the returned sample or be smaller than it, including
zero with nonempty hits. No total is used to claim every matching alert was read.
See the [OpenSearch search response and total semantics](https://docs.opensearch.org/latest/api-reference/search/).

Each source needs a nonempty timestamp string with a finite parsed instant and
an object `rule` with a nonnegative safe integer level, either a JSON number or
an integer string. Timestamps must be nonincreasing in the returned sample and
strictly newer than the committed cursor. These checks rely on this exact
descending timestamp sort, no offset and strict `gt` query; equal timestamps
within a sample are allowed. The original source strings and mapping remain.

Consumed optional string fields, rule/compliance/MITRE string arrays and
agent/manager/decoder/data object containers are checked when present. Numeric
or string destination ports are retained. Absent/null optional metadata keeps
the existing fallbacks, and unused extension fields remain allowed. This is a
consumed-field guard, not full Wazuh schema validation or normalization.

A rejected batch never reaches ID reservation, scoring, storage, cursor commit
or notification, including when a valid first row precedes a malformed row.
The existing error handler logs a fixed response-validation diagnostic and the
guard releases when the operation settles. A later tick can retry from the old
cursor. JSON decoding failures also use a fixed diagnostic without echoing
payloads. Other transport, scoring and subscriber errors retain their existing
logging behavior; this does not claim comprehensive log redaction.

## Cursor commit boundary

The poll snapshots the newest returned timestamp as a candidate. It scores the
whole batch, stores it in memory and applies the normal 500-alert retention cap,
then commits that candidate as its cursor before invoking the synchronous
subscriber. A scoring failure leaves the previous cursor unchanged and stores
none of that batch, so a later scheduled request can retry from the previous
cursor. The scorer uses `Promise.all`: one rejected item prevents batch storage,
but does not cancel any other scoring work already in progress. Late settlement
of those siblings cannot store the rejected batch.

A synchronous subscriber failure happens after storage and cursor commit. It is
logged by the existing poll error handler; it does not roll back or replay that
batch, and notification delivery is not guaranteed. The guard remains held
through notification, including callback reentry into the scheduled poll.
Returned subscriber promises are still not awaited.

Public `addAlerts`, used by HTTP ingestion, retains its existing behavior: a
synchronous notification error rejects the call after the rows are stored. The
HTTP route may therefore return an error for an already stored batch, and a
caller retry may duplicate it. HTTP and file ingestion never move the poll
cursor and are not serialized by its guard. File watching also keeps its prior
read-position behavior, which advances before parsing/scoring succeeds; this
change does not add JSONL replay or recovery.

## Scope and proposed followups

This is a process-local cursor/storage boundary, not lossless ingestion. It does
not change the newest-100 descending query, strict `timestamp > cursor` predicate,
mapping, alert IDs, TLS options, scoring logic, or retained store. More than 100
matching arrivals, including arrivals while a failed batch is retried, can still
leave older records outside the fetched sample. New records sharing the committed
timestamp can be skipped. There is no source-ID deduplication across polls,
HTTP or file ingestion. The cursor and retained store are not durable across
restarts, and normal retention still evicts older alerts.
Repeated starts may still replace the subscriber callback under the existing API.

Before claiming lossless polling, maintainers would need to review pagination,
equal-timestamp handling, durable cursor/commit rules,
source identity/deduplication, and restart behavior. Bounded deadlines and
cancellation would require their own provider/runtime contract and fixtures.
These are followup proposals, not implemented features or adopted commitments.
This slice makes no authentication, TLS trust, remote deployment, or live Wazuh
compatibility claim.

## Offline validation

Use Bun 1.3.14 from `apps/server`:

```bash
bun install --frozen-lockfile --no-env-file
bun --no-env-file test
bun run --no-env-file typecheck
```

On the standalone polling branch, the full server suite has 221 tests:
81 existing cases, 12 single-flight scenarios, 9 cursor-commit scenarios,
and 119 polling-response scenarios.
Focus the polling scenarios with
`bun --no-env-file test src/poll-single-flight.test.ts src/poll-commit.test.ts src/poll-response.test.ts`.
The same full suite and TypeScript check run on Ubuntu and macOS in
`.github/workflows/poll-single-flight.yml` with the tracked server lock.

The new fixtures invoke the production `startAlertIngestion` API and capture its
real interval callback. They drive that callback deterministically while holding
fetch, JSON decoding, or scoring promises, verify that skipped ticks do not
queue, and confirm that a later tick uses the accepted batch's newest timestamp.
They also cover storage callback reentry, synchronous first-fetch startup
reentry, repeated starts, an empty result, and
recovery after fetch, HTTP, JSON, mapping, scorer, and subscriber failures. The
callback-failure fixture confirms the existing stored batch remains present.

The cursor fixtures use the real registered scoring backend seam and production
batch scorer. They verify retry query predicates after initial and later scoring
failure, no partial or late storage after a rejected sibling, cursor advance
after storage, no replay after subscriber failure, callback reentry, ordinary
retention/order, empty results, and public/file ingestion during held poll scoring.

The response fixtures also call production `startAlertIngestion`, count the real
registered scorer, and inspect actual query cursors and stored/notification
batches. They cover completion/shards, malformed consumed fields after valid
rows, timestamps/order, contradictory totals, omitted/legacy/lower-bound totals,
optional fallbacks, empty samples and later recovery. The new cases fail 101
and pass 18 against the prior implementation; all 119 pass with validation.
Existing guard/cursor fixtures retain their assertions and now supply complete
synthetic response envelopes.

Each scenario uses a fresh process, synthetic credentials, controlled fetch and
scoring, and cleared inherited Wazuh trust settings. No real polling interval,
Wazuh, model, SSH or provider is used. One cursor scenario watches an owned
temporary JSONL file; the others use a disposable missing path. The existing
HTTP integration fixture also points its JSONL fallback at a disposable missing
file. These tests establish the local commit/overlap contract, not a deployed data-loss
or polling-completeness guarantee.

## Maintenance notes

Keep guard acquisition before the first await and release in `finally` around the
whole operation. Keep timer registration idempotent and before the initial poll
can reenter application code. Do not release the guard at fetch completion while
response parsing or scoring remains pending. Keep the cursor assignment after
whole-batch preparation and storage and before notification; calling public `addAlerts`
there would notify before cursor commit. Preserve mapping, ID reservation and
TLS behavior when composing other contributions. Do not move storage into the
per-record scorer or claim an in-memory commit is durable ingestion.

Response-validation followup contributed by Ryan Wentzel, https://ryanwentzel.me.
