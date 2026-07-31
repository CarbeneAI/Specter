# Architecture: Investigation Ledger + Deterministic Scorer

**Status:** Implemented
**PRD:** `docs/investigation-ledger-prd.md`
**Repo:** Specter (public proof repo — CyberDefenseTactics / PurpleTeamOps teaching artifact)

---

## 1. System Overview & Goals

Specter's AI chat panel is currently stateless: `sendChatMessage()` runs a tool-use loop
against Claude and returns only the final text. Nothing about *how* Claude got there —
which tool calls it made, what evidence it saw, how many tokens it burned — survives past
the response. This feature adds two additive capabilities:

1. **Deterministic Scorer** — a zero-API-key, rules-only pre-triage that scores *every*
   ingested alert (0–100, banded `critical`→`noise`) before the LLM is ever invoked. It
   runs even when `ANTHROPIC_API_KEY` is unset, and its verdict rides along on the alert
   object through the existing WebSocket broadcast and REST payloads.
2. **Investigation Ledger** — a `bun:sqlite`-backed audit log. Every `/chat` call becomes
   one `investigations` row plus an ordered sequence of `investigation_steps` rows (each
   LLM turn, each tool call, each tool result). `GET /ledger/:id` replays it exactly.

### Goals
- **Additive only.** Every existing route, payload shape, and function signature keeps
  working unchanged for existing callers. New fields are optional/appended, never
  replacing or renaming existing ones.
- **Zero new runtime dependencies.** `bun:sqlite` is part of the Bun runtime. No ORM, no
  Kafka, no ClickHouse, no route framework — the existing flat `if (url.pathname === ...)`
  chain in `index.ts` is extended with regex-matched paths for the two new `:id`-style
  routes, nothing more.
- **IP boundary is a hard wall, not a suggestion.** `getScoringBackend()` is the *only*
  seam an alternative aggregated scoring backend would ever need to touch. No
  aggregation math, no cross-instance schema, no reputation model appears anywhere in this
  document or in the code it describes.
- **Teaching-legible.** Scoring weights live in one exported, commented constant. The
  ledger schema is documented inline. The seam is explained in a comment block that reads
  like a mini-lecture, because students will read this file.
- **Fail-open.** A `bun:sqlite` write failure (disk full, permissions) must never break
  the chat response. Ledger writes are wrapped defensively; the user always gets their
  analysis back.

### High-level flow

```
                        ┌─────────────────────────────────────────────┐
                        │              alert-ingest.ts                │
   Wazuh Indexer  ───►  │  poll / JSONL watch / HTTP ingest            │
   (poll/webhook)       │      │                                       │
                        │      ▼                                      │
                        │  scoreAndAttach() ──► scorer.ts               │
                        │      │                 (LocalDeterministicScorer,
                        │      │                  getScoringBackend() seam)
                        │      ▼
                        │  storeAlerts() ──► in-memory ring buffer
                        │      │              (alert.verdict attached)
                        └──────┼───────────────────────────────────────┘
                               │
                               ▼
                    WebSocket broadcast {type:'alert', data: alert}
                    (verdict rides along — client badges it)
                               │
                               ▼
                    ┌────────────────────┐        user asks Claude about
                    │   Vue client        │───────►  POST /chat
                    │  AlertRow badge      │                │
                    │  ScorerBadge.vue     │                ▼
                    └────────────────────┘        ┌─────────────────────┐
                                                    │    pai-client.ts     │
                                                    │  sendChatMessage()   │
                                                    │  instrumented loop   │
                                                    │   │ createInvestigation
                                                    │   │ appendStep (llm/tool_call/tool_result) × N
                                                    │   │ finalizeInvestigation
                                                    └───┼─────────────────┘
                                                        ▼
                                                   ledger.ts (bun:sqlite)
                                                        │
                                       GET /ledger, /ledger/:id, /ledger/:id/share
                                                        │
                                                        ▼
                                             LedgerView.vue (replay timeline)
```

---

## 2. Component Breakdown

| Component | File | Responsibility |
|---|---|---|
| **Scorer** | `apps/server/src/scorer.ts` | Pure, dependency-free scoring logic. Exports `ScoreVerdict`, `ScoringContext`, `ScoringBackend`, `LocalDeterministicScorer`, `getScoringBackend()`/`registerScoringBackend()` seam, `scoreAndAttach()` helper, and the single documented `SCORER_WEIGHTS` constant. |
| **Ledger storage** | `apps/server/src/ledger.ts` | Owns the `bun:sqlite` connection, schema migration, and every parameterized query. Exports `createInvestigation`, `appendStep`, `finalizeInvestigation`, `listInvestigations`, `getInvestigation`, `createShareToken`, `resolveShareToken`. No other file touches the DB directly. |
| **Investigation capture** | `apps/server/src/pai-client.ts` (modified) | Instruments the existing tool-use loop inside `sendChatMessage()` to emit ledger writes as it runs, without changing the function's external signature. Returns `investigationId` in `PAIChatResponse`. |
| **Ingestion wiring** | `apps/server/src/alert-ingest.ts` (modified) | Calls `scoreAndAttach()` at every alert-entry point (Indexer poll, JSONL watch, HTTP ingest) before `storeAlerts()`, so every alert in the in-memory store carries a `.verdict`. Supplies the scorer's frequency signal via an in-memory lookup closure (no new network calls). |
| **Route additions** | `apps/server/src/index.ts` (modified) | `GET /alerts/scored`, `GET /ledger`, `GET /ledger/:id`, `GET /ledger/:id/share`, `GET /ledger/share/:token` — all read-only (except the share-token *creation*, which is additive and idempotent). |
| **Scorer badge** | `apps/client/src/components/ScorerBadge.vue` | Small pill showing band + score with a hover tooltip listing `reasons`. Dropped into `AlertRow.vue`'s header row. |
| **Ledger view** | `apps/client/src/components/LedgerView.vue`, `LedgerList.vue`, `LedgerReplay.vue` | List of recent investigations → click through to a replay timeline (alert context → scorer verdict → each step → final analysis → token/duration footer). |
| **Ledger composable** | `apps/client/src/composables/useLedger.ts` | Fetches `/ledger` and `/ledger/:id`, mirrors the `usePAIChat.ts` pattern already in the codebase. |
| **App shell wiring** | `apps/client/src/App.vue` (modified) | Adds a view toggle (Live Dashboard ↔ Ledger) without touching the existing WebSocket/chat wiring. |

---

## 3. SQLite Schema

**File:** `apps/server/src/ledger.ts` (schema lives as an inline `SCHEMA_SQL` constant executed
via `db.exec()` on first connection — no separate migration tool, no new dependency).

**DB path:** `process.env.LEDGER_DB_PATH`, default `./data/ledger.sqlite`. Resolved and
validated by `resolveDbPath()` (see §8 Security). **Must be added to `.gitignore`** — the
current `.gitignore` only excludes `*.db*`, not `*.sqlite*` or `data/`.

```sql
-- One row per /chat call that produces (or attempts) an AI analysis.
-- id is a UUID v4 (crypto.randomUUID()) — unguessable by construction, so
-- GET /ledger/:id is already a safe permalink; no sequential IDs anywhere.
CREATE TABLE IF NOT EXISTS investigations (
  id                  TEXT PRIMARY KEY,
  created_at          TEXT NOT NULL,               -- ISO-8601, UTC
  session_id          TEXT NOT NULL,                -- from PAIChatRequest.session_id
  alert_context_json  TEXT,                         -- JSON array of WazuhAlert shown to Claude, or NULL
  scorer_verdict_json TEXT,                         -- JSON array of ScoreVerdict|null, aligned with alert_context_json
  model               TEXT NOT NULL,                -- e.g. 'claude-sonnet-4-20250514'
  system_prompt       TEXT NOT NULL,
  user_message        TEXT NOT NULL,
  final_analysis      TEXT,                         -- NULL until finalized
  input_tokens        INTEGER,                      -- summed across all turns, NULL until finalized
  output_tokens       INTEGER,
  duration_ms         INTEGER,
  status              TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'completed', 'error'))
);

CREATE INDEX IF NOT EXISTS idx_investigations_created
  ON investigations(created_at DESC);              -- GET /ledger?limit= sorts by recency

-- Ordered replay of one investigation: prompt → each tool call/result → final text.
-- `seq` is assigned by pai-client.ts as it walks the tool-use loop; ORDER BY seq
-- reconstructs the exact sequence Claude experienced.
CREATE TABLE IF NOT EXISTS investigation_steps (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id  TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  seq               INTEGER NOT NULL,
  type              TEXT NOT NULL CHECK (type IN ('llm', 'tool_call', 'tool_result')),
  payload_json      TEXT NOT NULL,                  -- shape depends on `type`, see §4
  created_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_steps_investigation
  ON investigation_steps(investigation_id, seq);

-- STRETCH: revocable, unguessable share links decoupled from the investigation id.
-- token = 24 random bytes (192 bits) hex-encoded via crypto.randomBytes — not derived
-- from the investigation id, so revoking/rotating it never touches investigations.
CREATE TABLE IF NOT EXISTS share_tokens (
  token             TEXT PRIMARY KEY,
  investigation_id  TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  created_at        TEXT NOT NULL,
  revoked_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_share_investigation
  ON share_tokens(investigation_id);
```

Connection pragmas set once at startup in `getDb()`:
```ts
db.exec('PRAGMA journal_mode = WAL;');   // safe concurrent reads while a write is in flight
db.exec('PRAGMA foreign_keys = ON;');    // ON DELETE CASCADE actually cascades
```

**Rationale for the two-table split:** `investigations` is the row you list (`GET
/ledger`) — cheap, fixed-width, one row per chat turn. `investigation_steps` is the
variable-length replay detail, only fetched on `GET /ledger/:id`. This keeps the list
endpoint fast without a `JOIN`/`GROUP BY` and matches exactly what the PRD's acceptance
criteria describe ("retrievable ledger record" + "replays it step-by-step").

---

## 4. TypeScript Interfaces

All new server-side types are additive to `apps/server/src/types.ts` and `scorer.ts` /
`ledger.ts`; the client mirrors them in `apps/client/src/types.ts` (matching the existing
convention where client and server keep parallel, hand-copied type files — there is no
shared package).

### 4.1 Scorer (`apps/server/src/scorer.ts`)

```ts
/** Alert bands, ordered most→least severe, plus 'noise' for alert-fatigue suppression candidates. */
export type ScoreBand = 'critical' | 'high' | 'medium' | 'low' | 'noise';

export interface ScoreVerdict {
  score: number;                    // 0-100, clamped
  band: ScoreBand;
  reasons: string[];                // human-readable, e.g. "rule level 12 (critical) (+55)"
  signals: Record<string, number>;  // named signal -> point contribution, for transparency/teaching
  backend: string;                  // which backend produced this, e.g. 'local-deterministic'
}

export interface ScoringContext {
  windowMs: number;                                    // frequency lookback window (informational, used in `reasons`)
  lookupFrequency?: (key: string) => number;            // key = `${srcip}:${rule.id}`; caller injects the implementation
}

/** The seam. A private backend implements this interface and calls registerScoringBackend()
 *  before first use — no other call site in this codebase changes. */
export interface ScoringBackend {
  name: string;
  score(alert: WazuhAlert, ctx: ScoringContext): Promise<ScoreVerdict>;
}
```

### 4.2 Ledger (`apps/server/src/ledger.ts`)

```ts
export type StepType = 'llm' | 'tool_call' | 'tool_result';

export interface LlmStepPayload {
  role: 'assistant';
  content: unknown;        // raw Anthropic content blocks for this turn
  stopReason: string;
  usage?: { input_tokens: number; output_tokens: number };
}

export interface ToolCallStepPayload {
  toolUseId: string;
  name: string;             // e.g. 'search_wazuh_alerts'
  input: Record<string, unknown>;
}

export interface ToolResultStepPayload {
  toolUseId: string;
  resultText: string;       // the formatted text sent back to Claude as tool_result
}

export interface InvestigationStep {
  id: number;
  investigationId: string;
  seq: number;
  type: StepType;
  payload: LlmStepPayload | ToolCallStepPayload | ToolResultStepPayload;
  createdAt: string;
}

/** Row shape for GET /ledger (list) — cheap, no steps. */
export interface InvestigationSummary {
  id: string;
  createdAt: string;
  sessionId: string;
  alertSummary: string | null;    // first alert's rule.description, or null
  verdict: ScoreVerdict | null;   // first alert's verdict, or null
  status: 'running' | 'completed' | 'error';
  model: string;
}

/** Full row shape for GET /ledger/:id. */
export interface InvestigationDetail extends InvestigationSummary {
  alertContext: WazuhAlert[] | null;
  verdicts: (ScoreVerdict | null)[] | null;  // aligned with alertContext, in case of multi-alert context
  systemPrompt: string;
  userMessage: string;
  finalAnalysis: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  durationMs: number | null;
  steps: InvestigationStep[];
}
```

### 4.3 Existing types extended (additive only)

`apps/server/src/types.ts` and its client mirror `apps/client/src/types.ts`:

```ts
// WazuhAlert — one new optional field, attached by scoreAndAttach() during ingestion.
export interface WazuhAlert {
  // ...unchanged existing fields...
  verdict?: ScoreVerdict;
}

// PAIChatResponse — one new optional field.
export interface PAIChatResponse {
  success: boolean;
  content?: string;
  error?: string;
  investigationId?: string;   // NEW — lets /chat callers build a permalink
}
```

No existing field is renamed, removed, or retyped anywhere in this feature.

---

## 5. New / Modified File List

**New files:**
- `apps/server/src/scorer.ts`
- `apps/server/src/ledger.ts`
- `apps/server/src/scorer.test.ts`
- `apps/server/src/ledger.test.ts`
- `apps/client/src/components/ScorerBadge.vue`
- `apps/client/src/components/LedgerView.vue`
- `apps/client/src/components/LedgerList.vue`
- `apps/client/src/components/LedgerReplay.vue`
- `apps/client/src/composables/useLedger.ts`

**Modified files:**
- `apps/server/src/types.ts` — add `verdict?` to `WazuhAlert`, `investigationId?` to `PAIChatResponse`.
- `apps/server/src/alert-ingest.ts` — call `scoreAndAttach()` at all three ingestion entry points; `addAlerts()` becomes `async`; export `getScoredAlerts()`.
- `apps/server/src/pai-client.ts` — instrument `sendChatMessage()`'s tool-use loop; return `investigationId`.
- `apps/server/src/index.ts` — add 5 new routes; `await` the now-async `addAlerts()` call.
- `apps/server/package.json` — add `"test": "bun test"` script (Bun's built-in test runner, zero new deps).
- `apps/client/src/types.ts` — mirror the additive type changes.
- `apps/client/src/components/AlertRow.vue` — render `<ScorerBadge>` in the header row.
- `apps/client/src/App.vue` — add a view toggle wiring in `LedgerView.vue` alongside the existing split panel.
- `.env.example` — document `LEDGER_DB_PATH` and `LEDGER_REDACT`.
- `.gitignore` — add `data/` (or `*.sqlite*`) so the ledger DB is never committed.

---

## 6. Instrumenting `sendChatMessage()` (the ledger hook point)

**Design decision:** the PRD describes this as "wrap `sendChatMessage`." A literal
*external* wrapper (a higher-order function that calls the existing `sendChatMessage` as a
black box) cannot see the intermediate tool calls happening *inside* the existing
`while (toolCallCount <= MAX_TOOL_CALLS)` loop — those are the most valuable part of the
replay. So the instrumentation happens **in place**, inside the function body, while the
function's external signature and return type stay identical (plus one additive optional
field). This is "wrapping the loop," not "wrapping the call."

All ledger calls are wrapped in `try/catch` and never rethrow — a `bun:sqlite` failure
must never turn a successful Claude analysis into a failed chat response (fail-open,
per §1 Goals).

```ts
export async function sendChatMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  alertContext?: WazuhAlert[],
  _sessionId: string = 'specter-dashboard'
): Promise<PAIChatResponse> {
  const startTime = Date.now();
  let investigationId: string | undefined;
  let seq = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  try {
    const apiKey = getApiKey();
    const systemPrompt = /* ...unchanged... */;
    const messages: any[] = /* ...unchanged... */;

    // Ledger: open the investigation before the first API call.
    // Verdicts ride along on alertContext[i].verdict — already attached by
    // alert-ingest.ts's scoreAndAttach(). No new scoring call happens here.
    try {
      investigationId = createInvestigation({
        sessionId: _sessionId,
        alertContext: alertContext ?? null,
        scorerVerdicts: alertContext?.map(a => a.verdict ?? null) ?? null,
        model: 'claude-sonnet-4-20250514',
        systemPrompt,
        userMessage,
      });
    } catch (e) {
      console.error('[Ledger] createInvestigation failed (continuing without ledger):', e);
    }

    let toolCallCount = 0;
    while (toolCallCount <= MAX_TOOL_CALLS) {
      const response = await fetch(/* ...unchanged Anthropic call... */);
      if (!response.ok) {
        /* ...unchanged error handling... */
        safeFinalize(investigationId, { status: 'error', durationMs: Date.now() - startTime, finalAnalysis: null, inputTokens: totalInputTokens, outputTokens: totalOutputTokens });
        return { success: false, error: `API error: ${response.status}` };
      }

      const data = await response.json() as any;
      totalInputTokens += data.usage?.input_tokens ?? 0;
      totalOutputTokens += data.usage?.output_tokens ?? 0;

      // Ledger: record this raw LLM turn (assistant content blocks, stop reason, usage).
      safeAppendStep(investigationId, seq++, 'llm', {
        role: 'assistant', content: data.content, stopReason: data.stop_reason,
        usage: data.usage,
      });

      if (data.stop_reason === 'tool_use') {
        toolCallCount++;
        const toolUseBlocks = (data.content as any[]).filter(b => b.type === 'tool_use');
        const toolResults: any[] = [];

        for (const toolUse of toolUseBlocks) {
          if (toolUse.name === 'search_wazuh_alerts') {
            // Ledger: record the call before executing it.
            safeAppendStep(investigationId, seq++, 'tool_call', {
              toolUseId: toolUse.id, name: toolUse.name, input: toolUse.input,
            });

            const searchResult = await searchWazuhAlerts(toolUse.input);
            const resultText = formatSearchResults(searchResult);

            // Ledger: record the result actually sent back to Claude.
            safeAppendStep(investigationId, seq++, 'tool_result', {
              toolUseId: toolUse.id, resultText,
            });

            toolResults.push({ type: 'tool_result', tool_use_id: toolUse.id, content: resultText });
          }
        }

        messages.push({ role: 'assistant', content: data.content });
        messages.push({ role: 'user', content: toolResults });
        continue;
      }

      // Final response.
      const content = (data.content as any[]).filter(b => b.type === 'text').map(b => b.text).join('\n');
      safeFinalize(investigationId, {
        status: 'completed', finalAnalysis: content,
        inputTokens: totalInputTokens, outputTokens: totalOutputTokens,
        durationMs: Date.now() - startTime,
      });
      return { success: true, content, investigationId };
    }

    safeFinalize(investigationId, { status: 'completed', finalAnalysis: '(max tool calls reached)', inputTokens: totalInputTokens, outputTokens: totalOutputTokens, durationMs: Date.now() - startTime });
    return { success: true, content: '...reached the analysis limit...', investigationId };
  } catch (error) {
    safeFinalize(investigationId, { status: 'error', finalAnalysis: null, inputTokens: totalInputTokens, outputTokens: totalOutputTokens, durationMs: Date.now() - startTime });
    return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}

// safeAppendStep / safeFinalize: thin try/catch wrappers around ledger.ts's
// appendStep/finalizeInvestigation. No-ops if investigationId is undefined
// (i.e. createInvestigation already failed) so the rest of the loop never
// has to null-check.
```

Call site impact in `index.ts`'s `POST /chat` handler: **zero required changes** — it
already does `return new Response(JSON.stringify(response), ...)`, and `response` now just
has one extra optional key. The client's `usePAIChat.ts` can opt in to reading
`data.investigationId` to build a "View full investigation →" link; if it doesn't, nothing
breaks.

---

## 7. Wiring the Scorer into Ingestion and the Alert Broadcast

**Frequency signal without a network round-trip.** The PRD suggests optionally querying
`searchWazuhAlerts` (in `pai-client.ts`) for the frequency signal. That would mean scoring
100 alerts per 30-second poll each firing a network call against the Wazuh Indexer —
slow, non-deterministic (depends on indexer latency/availability), and it would create an
import cycle risk between `alert-ingest.ts` and `pai-client.ts`. Instead, `alert-ingest.ts`
already holds up to 500 recent alerts in memory (`MAX_ALERTS`); the frequency signal is
computed **locally, synchronously, for free** by injecting a `lookupFrequency` closure over
that same in-memory array. This keeps the scorer genuinely deterministic (same store state
→ same verdict, every time) and keeps `scorer.ts` dependency-free of both `pai-client.ts`
and `alert-ingest.ts` (dependency inversion: `scorer.ts` defines the interface, the caller
injects the implementation).

`apps/server/src/alert-ingest.ts` additions:

```ts
import { scoreAndAttach } from './scorer';
import type { ScoringContext } from './scorer';

const FREQUENCY_WINDOW_MS = 24 * 60 * 60 * 1000;

function buildScoringContext(): ScoringContext {
  return {
    windowMs: FREQUENCY_WINDOW_MS,
    lookupFrequency: (key: string) => {
      const [srcip, ruleId] = key.split(':');
      const cutoff = Date.now() - FREQUENCY_WINDOW_MS;
      return alerts.filter(a =>
        a.rule.id === ruleId &&
        (a.srcip || '') === srcip &&
        new Date(a.timestamp).getTime() >= cutoff
      ).length;
    },
  };
}
```

Every place that currently calls `storeAlerts(newAlerts)` is updated to score first:

| Call site | Before | After |
|---|---|---|
| `pollWazuhIndexer()` (already `async`) | `storeAlerts(alertsWithIds);` | `storeAlerts(await scoreAndAttach(alertsWithIds, buildScoringContext()));` |
| `watchFile()`'s `fs.watch` callback (sync) | `storeAlerts(newAlerts);` | `scoreAndAttach(newAlerts, buildScoringContext()).then(storeAlerts);` |
| `addAlerts()` (HTTP ingest, was sync) | `storeAlerts(alertsWithIds); return alertsWithIds;` | becomes `async`: `const scored = await scoreAndAttach(alertsWithIds, buildScoringContext()); storeAlerts(scored); return scored;` |

`addAlerts()` becoming `async` is the one non-cosmetic signature change in this feature.
Its single call site, `POST /alerts/ingest` in `index.ts`, adds one `await`. The HTTP
contract (request/response JSON shape) is unchanged.

`storeAlerts()` itself needs no changes — `verdict` just rides along as an extra property
on each `WazuhAlert` object all the way into the in-memory ring buffer, and from there into
the existing `{type:'alert', data: alert}` WebSocket broadcast in `index.ts` — satisfying
"attach `verdict` to the alert broadcast" with no changes to the broadcast code itself.

`getRecentAlerts()`, `filterAlerts()`: unchanged, verdicts ride along automatically.

New export for the `/alerts/scored` route:
```ts
export function getScoredAlerts(limit = 100, band?: ScoreBand): WazuhAlert[] {
  let result = alerts.filter(a => !band || a.verdict?.band === band);
  return result.slice(-limit).reverse();
}
```

---

## 8. New API Endpoints

All new routes are inserted into the existing flat `if (url.pathname === ...)` chain in
`index.ts` (no router library — zero new deps). The two `:id`/`:token` routes use plain
regex matches, checked in this order (most-specific first, matching how the existing code
already special-cases things):

```ts
const shareTokenMatch = url.pathname.match(/^\/ledger\/share\/([0-9a-f]{48})$/);
const createShareMatch = url.pathname.match(/^\/ledger\/([0-9a-f-]{36})\/share$/);
const investigationMatch = url.pathname.match(/^\/ledger\/([0-9a-f-]{36})$/);
```

| Method | Path | Request | Response | Notes |
|---|---|---|---|---|
| `GET` | `/alerts/scored` | query: `limit` (default 100), `band` (optional, one of `critical\|high\|medium\|low\|noise`) | `200 WazuhAlert[]` (each with `.verdict`) | Same shape as `/alerts/recent`, guaranteed-scored + filterable by band for noise reduction. |
| `GET` | `/ledger` | query: `limit` (default 50, max 200) | `200 { investigations: InvestigationSummary[] }` | Read-only. No filters beyond limit in v1. |
| `GET` | `/ledger/:id` | `:id` = UUID | `200 { investigation: InvestigationDetail }` / `404 { error: 'Not found' }` | `:id` validated against a UUID regex *before* it ever reaches SQL — malformed input short-circuits to 404 without a query. |
| `GET` | `/ledger/:id/share` | `:id` = UUID | `200 { token: string, url: string }` / `404` if investigation doesn't exist | **Stretch.** Idempotent-ish: creates a token on first call; current design creates a new token per call (simplest; revocation model is a stretch-of-the-stretch). `url` = `${request origin}/ledger/share/${token}`. |
| `GET` | `/ledger/share/:token` | `:token` = 48 hex chars | `200 { investigation: InvestigationDetail }` / `404` | Public replay view. Does not require or expose the internal investigation `id` relationship beyond what's already visible in the returned payload. |
| `POST` | `/chat` (existing, response extended) | unchanged | adds optional `investigationId?: string` | No other change to this route. |

All `/ledger*` and `/alerts/scored` routes are `GET`-only — no mutation surface, satisfying
"`/ledger` read-only" from the PRD's security gate. The one endpoint that *writes* is
`GET /ledger/:id/share`, which only inserts a new opaque token row; it never mutates an
`investigations` or `investigation_steps` row. This is called out explicitly for security review:
using `GET` for a state-changing action is a deliberate, narrow exception to REST purism
that keeps the route regex simple and the write blast-radius (one new row, no existing row
touched) trivial to audit — flag if this needs to move to `POST` in review.

---

## 9. Security Considerations (mapped to the PRD's constraints)

| Constraint | Implementation |
|---|---|
| **Parameterized SQL only** | Every query in `ledger.ts` uses `bun:sqlite`'s `db.query(sql).run(...params)` / `.get(...params)` / `.all(...params)` with positional `?` placeholders. No template-literal SQL, anywhere, ever. `scorer.test.ts`/`ledger.test.ts` include a grep-style assertion (or a code-review checklist item) that no `${}` appears inside a string passed to `db.query`/`db.exec` outside the fixed `SCHEMA_SQL` constant. |
| **Unguessable permalink tokens** | Investigation `id` is `crypto.randomUUID()` (v4, 122 bits of randomness) — already safe to expose directly, no sequential IDs anywhere. The stretch `share_tokens.token` is `crypto.randomBytes(24).toString('hex')` (192 bits), generated independently of the investigation id, so guessing one gives no information about the other. |
| **No secrets in the ledger** | `ANTHROPIC_API_KEY` and Wazuh credentials never appear in any value passed to `createInvestigation`/`appendStep` — they're read from `process.env` inside `pai-client.ts`/`alert-ingest.ts` and used only in `Authorization`/`x-api-key` headers, never placed into `systemPrompt`, `userMessage`, tool payloads, or `finalAnalysis`. As defense-in-depth, `ledger.ts` runs a cheap regex scrub (`/sk-ant-[a-zA-Z0-9-]+/g` → `[redacted]`) over `system_prompt`, `user_message`, and `final_analysis` immediately before insert — belt-and-suspenders in case a user pastes a key into the chat box. The PRD's `LEDGER_REDACT=1` broader-redaction toggle is documented as a stretch flag in `.env.example` but not required for v1 acceptance. |
| **Path-safe `LEDGER_DB_PATH`** | `resolveDbPath()` in `ledger.ts`: rejects any value containing a NUL byte, resolves the path with Node's `path.resolve()` (collapses `..` segments deterministically relative to CWD), and `mkdirSync(dirname(path), { recursive: true })` before opening — so a misconfigured path fails loudly at startup instead of silently writing somewhere unexpected. This is an admin-set env var (not user input), but it's treated with the same rigor as if it weren't. |
| **`/ledger` read-only, no injection via `:id`** | See §8 — all routes are `GET`; `:id` and `:token` are validated by regex against the URL pattern *before* the handler runs a query, and again inside `ledger.ts`'s `getInvestigation`/`resolveShareToken` (defense in depth: even if a future route change relaxes the URL regex, the storage layer still refuses malformed IDs). Malformed IDs return `404`, never a SQL error message (no information leak about query structure). |

---

## 10. Testing Strategy

Bun ships a Jest-compatible test runner (`bun:test`) — zero new dependencies. Add
`"test": "bun test"` to `apps/server/package.json`.

**`apps/server/src/scorer.test.ts`**
- Determinism: same `WazuhAlert` + same `ScoringContext` → identical `ScoreVerdict` across repeated calls (acceptance criterion: "scorer determinism").
- Band boundaries: rule levels 0, 2, 3, 6, 7, 11, 12, 15 each land in the expected band per `SCORER_WEIGHTS`/`SCORE_BANDS`.
- MITRE presence upweights score; absence does not.
- Frequency downweight: inject a `lookupFrequency` stub returning a count above `FREQUENCY_NOISE_THRESHOLD` for a low-severity rule → verdict shifts toward `noise`, `reasons` includes the frequency line.
- Suppressed group downweight fires only when `rule.groups` intersects `SUPPRESSED_GROUPS`.
- `getScoringBackend()` returns the same instance across calls (singleton) and `registerScoringBackend()` swaps it — proves the seam works without touching call sites.
- No-key degradation: scorer runs and returns a verdict with `ANTHROPIC_API_KEY` unset (it never reads that env var at all — test asserts by unsetting it in the test's env and confirming no throw).

**`apps/server/src/ledger.test.ts`** (uses a temp `LEDGER_DB_PATH` per test, cleaned up in `afterEach`)
- `createInvestigation` → `appendStep` ×N → `finalizeInvestigation` → `getInvestigation` round-trips every field, `steps` returned in `seq` order.
- `listInvestigations(limit)` returns most-recent-first, respects `limit`, caps at 200.
- Malformed `id` (not UUID-shaped) passed to `getInvestigation` returns `null` without throwing or touching SQLite.
- `resolveDbPath()`: rejects a path containing `\0`; creates parent directories that don't yet exist; two calls with the same `LEDGER_DB_PATH` reuse the same connection (no "database is locked" errors).
- Parameterized-query safety: a `WazuhAlert.rule.description` containing `'; DROP TABLE investigations; --` round-trips as inert text (proves parameterization, not sanitization, is doing the work).
- `createShareToken`/`resolveShareToken`: token resolves to the right investigation; a token for a non-existent investigation ID is refused at creation (`null`); a revoked token (`revoked_at` set) fails to resolve.

**Integration (in `index.ts`'s existing manual/README-driven QA, or a lightweight `bun test` hitting `Bun.serve` on an ephemeral port)**
- `POST /chat` with `ANTHROPIC_API_KEY` unset still returns a clean `success:false` error — no ledger row left half-written (or a `status:'error'` row exists, per design — pick one and assert it during QA).
- `POST /alerts/ingest` → alert appears via `GET /alerts/scored` with a non-null `.verdict` and no `ANTHROPIC_API_KEY` set.
- `GET /ledger/:id` for a real investigation replays steps in order and matches what was captured during a live `POST /chat` call with a stubbed/mocked Anthropic response.
- `GET /ledger/not-a-uuid` → `404`, not `500`.

**QA acceptance mapping:** scorer determinism ✅ (scorer.test.ts), ledger persistence + replay ✅ (ledger.test.ts + integration), no-key degradation ✅ (scorer.test.ts + integration), parameterized-query safety ✅ (ledger.test.ts SQLi round-trip test).


