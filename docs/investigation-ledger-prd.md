# PRD — Investigation Ledger + Deterministic Scorer

**Repo:** Specter. **Status:** implemented.
**Positioning:** working reference and teaching artifact for the CyberDefenseTactics / PurpleTeamOps "build your own Purple Team tool" course.

## 1. Why

Specter's AI chat is ephemeral — when Claude analyzes an alert, the reasoning, evidence,
and tool calls vanish when the tab closes. This PRD adds two capabilities borrowed (as
*patterns*, not code) from AiSOC (MIT):

1. **Investigation Ledger** — persist every AI investigation as an auditable, replayable
   record with a shareable permalink. The "receipt" that makes future autonomous response
   defensible.
2. **Deterministic Scorer** — a no-API-key, rules-only pre-triage that scores every alert
   before the LLM is ever called. Cheap noise reduction + graceful degradation when no key
   is set. Its verdict is recorded into each Ledger entry.

## 2. Scope boundary

- **In scope:** the Ledger; a `LocalDeterministicScorer`; a `ScoringBackend` interface
  (the seam).
- **Deliberately out of scope:** any cross-instance aggregated or reputation-weighted
  scoring model. Single-host scoring and fleet-wide signal aggregation are different
  problems with different failure modes, and the seam exists so the second can be added
  later without this module growing to accommodate it. No aggregation math, shared
  schema, or reputation logic belongs in this file.

The architectural case for aggregation across a fleet, including the parts that are not
solved, is published without restriction at
[endpoint-mesh](https://github.com/CarbeneAI/endpoint-mesh).

## 3. Deterministic Scorer

New module `apps/server/src/scorer.ts`.

```ts
export interface ScoreVerdict {
  score: number;          // 0–100
  band: 'critical' | 'high' | 'medium' | 'low' | 'noise';
  reasons: string[];      // human-readable, e.g. "rule level 12 (+40)", "seen 1500x/24h (+15)"
  signals: Record<string, number>;  // named signal → contribution, for transparency/teaching
  backend: string;        // 'local-deterministic' — identifies which backend scored it
}

export interface ScoringBackend {
  name: string;
  score(alert: WazuhAlert, ctx: ScoringContext): Promise<ScoreVerdict>;
}
```

`LocalDeterministicScorer` (pure, synchronous-ish, no LLM) combines transparent signals:
- Wazuh rule level → base band (reuse existing thresholds: 12+ crit, 7–11 high, 3–6 med).
- Frequency: optionally query `searchWazuhAlerts` for same src_ip/rule_id over 24h; high
  repetition on a low-severity rule => downweight toward `noise` (that's the alert-fatigue win).
- MITRE presence => small upweight.
- Suppressed rule / known-benign group => downweight.
All weights live in one exported, documented constant so students can read/tune them.

Seam usage: the active backend comes from a factory `getScoringBackend()` that returns
`LocalDeterministicScorer` by default. A future private backend registers here — no other
call site changes.

Wire-in: score alerts as they're ingested (`alert-ingest.ts`) and attach `verdict` to the
alert broadcast so the UI can badge it. Expose `GET /alerts/scored` and include verdict in
existing alert payloads (additive, non-breaking).

## 4. Investigation Ledger

Storage: **`bun:sqlite`** (built into Bun — zero new dependency, on-brand). DB file path
from env `LEDGER_DB_PATH` (default `./data/ledger.sqlite`), gitignored.

Schema (one investigation = one AI chat turn that may include tool calls):
- `investigations(id TEXT pk, created_at, session_id, alert_context_json, scorer_verdict_json,
   model, system_prompt, user_message, final_analysis, input_tokens, output_tokens,
   duration_ms, status)`
- `investigation_steps(id, investigation_id fk, seq, type['llm'|'tool_call'|'tool_result'],
   payload_json, created_at)` — ordered replay of prompt → each tool call + args + result →
   final text.

Hook point: wrap `sendChatMessage` in `pai-client.ts`. Capture system prompt, message chain,
each `search_wazuh_alerts` call + its result, final content, model, token usage (from API
`usage`), timing. Write one investigation + N steps. Return the `investigationId` in
`PAIChatResponse` so `/chat` can hand back a permalink.

Redaction: reuse the "pseudonymize before persist" idea only if trivial; otherwise store raw
(local, self-hosted) but document the toggle `LEDGER_REDACT=1` as a stretch.

Routes (additive to index.ts):
- `GET /ledger?limit=` — list recent investigations (id, created_at, alert summary, verdict, status).
- `GET /ledger/:id` — full replayable record (investigation + ordered steps).
- (stretch) `GET /ledger/:id/share` — read-only permalink token.

Frontend (Vue): a **Ledger view** that renders an investigation as a replay timeline
(alert context → scorer verdict → each tool call/result → final analysis, with tokens +
duration). A small **scorer badge** on `AlertRow.vue` showing band + score. Keep Tokyo Night.

## 5. Non-negotiables

- No new runtime deps beyond what Bun ships (bun:sqlite is fine). No Kafka/ClickHouse/etc.
- Additive & non-breaking: existing routes/payloads keep working.
- Everything documented for teaching: the scorer weights, the ledger schema, and the seam
  each get a short "how this works / why" comment block.
- Security gates: SQL via parameterized queries only; permalink tokens
  unguessable; no secrets in ledger; path traversal safe on `LEDGER_DB_PATH`; `/ledger`
  read-only, no injection via `:id`.

## 6. Acceptance

- Running an AI analysis creates a retrievable ledger record; `GET /ledger/:id` replays it
  step-by-step.
- Every ingested alert carries a deterministic verdict with visible reasons; the app still
  boots and scores with `ANTHROPIC_API_KEY` unset.
- `getScoringBackend()` is the only place to swap in a different scorer.
- QA covers: scorer determinism, ledger persistence + replay, no-key degradation,
  parameterized-query safety.
