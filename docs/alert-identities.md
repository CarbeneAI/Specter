# Alert identity and retention

Specter uses each alert's numeric `id` for Vue rendering, selection, and individual
dismissal. It retains at most 500 alerts in memory. IDs must not come from that
array's length: after trimming, the same ID could identify an unrelated alert,
and a browser's dismissal set would hide the new alert as well.

## Current contract

- Indexer polling and `addAlerts()` reserve from the same process-local counter.
  The JSONL watcher and HTTP ingestion use `addAlerts()`.
- The server reserves IDs synchronously before asynchronous scoring starts.
  Concurrent batches share one sequence, even if scoring finishes out of order.
- Incoming `id` values are replaced. Input objects are not mutated.
- Retention does not reset the sequence. Failed scoring may leave gaps, which
  are intentional; callers must not assume that IDs are contiguous.
- The returned, stored, and broadcast objects carry the same assigned IDs.
- Storage and broadcast order follows scoring completion, not numeric ID order.

The sequence is local to one server process. It resets on restart and does not
identify a Wazuh document persistently or deduplicate repeat ingestion. Refresh
dashboard tabs after restarting the server so prior dismissal and selection state
cannot match IDs from a new run. Automatically resetting browser state when the
server instance changes remains a proposed follow-up.

This change does not alter the 500-alert memory limit, persist alerts, or repair
the poller's newest-100 query and timestamp watermark. Burst delivery, timestamp
ties, retry recovery, and source-level deduplication need separate work.

## Offline verification

From `apps/server`:

```sh
bun install --frozen-lockfile --no-env-file
bun test --no-env-file src/alert-ingest.test.ts
bun test --no-env-file
bun run --no-env-file typecheck
```

The four identity regressions run ingestion in disposable child processes. They
exercise 1,600 alerts across retention, delayed scoring completed out of order,
mixed polling/file/HTTP entry points, and recovery after a scoring failure. The
mixed-source fixture uses a temporary JSONL file, the real watcher, a mocked
Indexer response, and the same callback used for WebSocket broadcasting. It calls
the HTTP ingestion function directly; the existing integration suite tests the
HTTP route separately. No fixture contacts a real Indexer or model provider.

The Alert ingestion CI workflow runs the full server suite and typecheck on Linux
and macOS. This verifies the file-watcher fixture on both supported CI platforms;
it does not establish live Wazuh compatibility or production readiness.
