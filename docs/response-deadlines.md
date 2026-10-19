# Wazuh and model-discovery response deadlines

Prepared by Ryan Wentzel, https://ryanwentzel.me.

Wazuh polling, direct Wazuh search, and Ollama model discovery now request a fixed 30-second native abort signal. This is a new bounded request/body policy for these three paths, not a performance budget derived from deployment measurements. There is no new environment setting or retry policy.

The signal remains attached through asynchronous response-body consumption. Receiving HTTP headers does not cancel the deadline. A stalled successful JSON body or a stalled direct-search error body therefore cannot leave the caller awaiting that body indefinitely. The deadline starts when the signal is created immediately before fetch; prior configuration/CA-file reads are outside it.

Direct search preserves its existing HTTP error-body read and error result under the same deadline. If that body stalls, the native abort reaches the existing search error path. Polling and discovery do not read non-OK bodies, so they abort that request immediately before returning their existing error outcome. Successful requests retain the native runtime-owned timer lifetime; this change does not promise immediate timer cancellation. Fixtures verify that these signals do not keep a completed child process running.

Discovery retains its existing `[]` result for failures and a valid empty model list. This contribution does not make those states distinguishable in the API. Search retains its error field. A failed poll request cannot update memory, notify subscribers or advance its timestamp. With the separate [poll-continuity contribution](https://github.com/CarbeneAI/Specter/pull/7), the existing guard remains held through actual request/body settlement, then releases for the next scheduled tick. There is no detached `Promise.race` or queued catch-up poll.

This independent change does not introduce certificate trust behavior. Integrate the separate [Wazuh TLS contribution](https://github.com/CarbeneAI/Specter/pull/6) for request-scoped CA validation and redirect protection. The composed checks retain that trust policy and polling response validation. No TLS setting, search query, result validator, source ID allocator or score/store/cursor ordering is changed here.

## Reproduce the offline and loopback checks

Use Bun 1.3.14 and an available `openssl` executable:

```sh
cd apps/server
bun install --frozen-lockfile --no-env-file
bun test --no-env-file
bun run --no-env-file typecheck
```

The focused suite is `bun test --no-env-file src/response-deadline.test.ts`. It runs production entrypoints in isolated Bun subprocesses against disposable loopback HTTP/HTTPS servers, with temporary certificates and no external provider calls. Its assertions cover headers and successful/error bodies, real server-stream cancellation, rejected late writes, slow successful bodies, unchanged return shapes, preserved poll memory/cursor, and later retry.

Most cases capture the production `30_000` value and accelerate only the native signal to 350 milliseconds; they do not mock fetch or resolve a fake timeout error. One case uses the actual 30-second native deadline and observes body abort. Successful child processes exit naturally after their owned server is stopped. These are Bun 1.3.14 fixture results, not an assurance for every runtime, proxy or deployment.

## Limits and proposed followups

- This policy bounds asynchronous network/body waits. It cannot interrupt synchronous JSON parsing, mapping, scoring, SQLite work or arbitrary callbacks, and is not a whole-poll or whole-chat deadline.
- Ollama generation keeps its existing 30-minute timer, which is cleared when response headers arrive. Its response-body reads remain unbounded by that timer and are outside this contribution. Generation, Anthropic and SSH paths need separate review.
- No new input-size limit, pagination, durable cursor, lossless-ingestion claim, authentication or destination authorization is introduced.
- A later maintainer proposal should make model-discovery failure distinct from a valid empty list, define generation/body cancellation separately, and use measured workloads before selecting resource budgets or configurable deadlines.
- Deployment/proxy compatibility and production capacity require separate evidence. The new CI runs only standard Ubuntu/macOS fixtures.
