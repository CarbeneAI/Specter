/**
 * Specter - Investigation Ledger
 *
 * Owns the bun:sqlite connection, schema, and every parameterized query for the
 * investigation audit log described in .devteam/docs/architecture-scorer-ledger.md (sections 3-4, 9).
 *
 * Every `/chat` call becomes one `investigations` row plus an ordered sequence of
 * `investigation_steps` rows (each LLM turn, each tool call, each tool result).
 * `getInvestigation(id)` replays it exactly, in `seq` order.
 *
 * SECURITY (docs/architecture-scorer-ledger.md section 9):
 *  - Parameterized SQL only. Every query below uses bun:sqlite's `?` positional
 *    placeholders with bound params. No template-literal / `${}` SQL anywhere in
 *    this file except the fixed `SCHEMA_SQL` DDL constant (which contains no
 *    interpolated values -- it is a static string).
 *  - Defense-in-depth secret scrub: `sk-ant-...` patterns are redacted out of
 *    system_prompt / user_message / final_analysis before they ever reach SQLite,
 *    in case a user pastes a key into the chat box.
 *  - `LEDGER_DB_PATH` is treated as untrusted input even though it's admin-set:
 *    resolveDbPath() rejects NUL bytes and resolves via path.resolve() before the
 *    parent directory is created.
 *  - `getInvestigation(id)` validates `id` against a UUID regex BEFORE any SQL
 *    runs -- malformed ids short-circuit to `null` without touching SQLite.
 *
 * SCOPE NOTE: share-token functionality (`createShareToken`/`resolveShareToken`,
 * the `share_tokens` table) is deferred/out of scope for this build. Do not add it
 * here -- only `investigations` and `investigation_steps` exist in this schema.
 */

import { Database } from 'bun:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { WazuhAlert } from './types';
// Type-only import: erased at compile time, so this has no runtime dependency on
// scorer.ts existing yet (Phase A and Phase B are parallel, independent builds).
import type { ScoreVerdict } from './scorer';

// ---------------------------------------------------------------------------
// Types (docs/architecture-scorer-ledger.md section 4.2)
// ---------------------------------------------------------------------------

export type StepType = 'llm' | 'tool_call' | 'tool_result';

export interface LlmStepPayload {
  role: 'assistant';
  content: unknown; // raw Anthropic content blocks for this turn
  stopReason: string;
  usage?: { input_tokens: number; output_tokens: number };
}

export interface ToolCallStepPayload {
  toolUseId: string;
  name: string; // e.g. 'search_wazuh_alerts'
  input: Record<string, unknown>;
}

export interface ToolResultStepPayload {
  toolUseId: string;
  resultText: string; // the formatted text sent back to Claude as tool_result
}

export interface InvestigationStep {
  id: number;
  investigationId: string;
  seq: number;
  type: StepType;
  payload: LlmStepPayload | ToolCallStepPayload | ToolResultStepPayload;
  createdAt: string;
}

/** Row shape for GET /ledger (list) -- cheap, no steps. */
export interface InvestigationSummary {
  id: string;
  createdAt: string;
  sessionId: string;
  alertSummary: string | null; // first alert's rule.description, or null
  verdict: ScoreVerdict | null; // first alert's verdict, or null
  status: 'running' | 'completed' | 'error';
  model: string;
}

/** Full row shape for GET /ledger/:id. */
export interface InvestigationDetail extends InvestigationSummary {
  alertContext: WazuhAlert[] | null;
  verdicts: (ScoreVerdict | null)[] | null; // aligned with alertContext
  systemPrompt: string;
  userMessage: string;
  finalAnalysis: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  durationMs: number | null;
  steps: InvestigationStep[];
}

export interface CreateInvestigationParams {
  sessionId: string;
  alertContext: WazuhAlert[] | null;
  scorerVerdicts: (ScoreVerdict | null)[] | null;
  model: string;
  systemPrompt: string;
  userMessage: string;
}

export interface FinalizeInvestigationParams {
  status: 'completed' | 'error';
  finalAnalysis: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  durationMs: number | null;
}

// Internal row shapes as returned raw by bun:sqlite (snake_case columns).
interface InvestigationRow {
  id: string;
  created_at: string;
  session_id: string;
  alert_context_json: string | null;
  scorer_verdict_json: string | null;
  model: string;
  system_prompt: string;
  user_message: string;
  final_analysis: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  duration_ms: number | null;
  status: string;
}

interface StepRow {
  id: number;
  investigation_id: string;
  seq: number;
  type: string;
  payload_json: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Schema (docs/architecture-scorer-ledger.md section 3) -- investigations + investigation_steps ONLY.
// share_tokens is deferred/out of scope; do not add it here.
// ---------------------------------------------------------------------------

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS investigations (
  id                  TEXT PRIMARY KEY,
  created_at          TEXT NOT NULL,
  session_id          TEXT NOT NULL,
  alert_context_json  TEXT,
  scorer_verdict_json TEXT,
  model               TEXT NOT NULL,
  system_prompt       TEXT NOT NULL,
  user_message        TEXT NOT NULL,
  final_analysis      TEXT,
  input_tokens        INTEGER,
  output_tokens       INTEGER,
  duration_ms         INTEGER,
  status              TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'completed', 'error'))
);

CREATE INDEX IF NOT EXISTS idx_investigations_created
  ON investigations(created_at DESC);

CREATE TABLE IF NOT EXISTS investigation_steps (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id  TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  seq               INTEGER NOT NULL,
  type              TEXT NOT NULL CHECK (type IN ('llm', 'tool_call', 'tool_result')),
  payload_json      TEXT NOT NULL,
  created_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_steps_investigation
  ON investigation_steps(investigation_id, seq);
`;

// ---------------------------------------------------------------------------
// Secret scrub (defense-in-depth, docs/architecture-scorer-ledger.md section 9)
// ---------------------------------------------------------------------------

const SECRET_PATTERN = /sk-ant-[a-zA-Z0-9-]+/g;
const REDACTED = '[redacted]';

function scrubSecrets(value: string): string;
function scrubSecrets(value: string | null | undefined): string | null;
function scrubSecrets(value: string | null | undefined): string | null {
  if (value == null) return null;
  return value.replace(SECRET_PATTERN, REDACTED);
}

// ---------------------------------------------------------------------------
// UUID guard (docs/architecture-scorer-ledger.md section 9 -- checked before any SQL runs)
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

let dbInstance: Database | null = null;
let dbInstancePath: string | null = null;

/**
 * Resolves LEDGER_DB_PATH (default './data/ledger.sqlite') to an absolute path,
 * rejecting NUL bytes and ensuring the parent directory exists.
 *
 * Treated with the same rigor as user input even though it's admin-set: a
 * misconfigured path should fail loudly at startup instead of silently writing
 * somewhere unexpected.
 */
export function resolveDbPath(): string {
  const raw = process.env.LEDGER_DB_PATH ?? './data/ledger.sqlite';
  if (raw.includes('\0')) {
    throw new Error('LEDGER_DB_PATH must not contain a NUL byte');
  }
  const absolute = resolve(raw);
  mkdirSync(dirname(absolute), { recursive: true });
  return absolute;
}

/**
 * Opens (or reuses) the singleton bun:sqlite connection for the resolved
 * LEDGER_DB_PATH, applying pragmas and the schema on first open. Two calls with
 * the same LEDGER_DB_PATH reuse the same connection -- no "database is locked"
 * errors from repeatedly reopening the same file.
 */
export function getDb(): Database {
  const path = resolveDbPath();
  if (dbInstance && dbInstancePath === path) {
    return dbInstance;
  }
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // best-effort close of the previous connection; never block opening the new one
    }
  }
  const db = new Database(path, { create: true });
  db.exec('PRAGMA journal_mode = WAL;'); // safe concurrent reads while a write is in flight
  db.exec('PRAGMA foreign_keys = ON;'); // ON DELETE CASCADE actually cascades
  db.exec(SCHEMA_SQL);
  dbInstance = db;
  dbInstancePath = path;
  return db;
}

// ---------------------------------------------------------------------------
// Row -> domain object mapping
// ---------------------------------------------------------------------------

function rowToSummary(row: InvestigationRow): InvestigationSummary {
  let alertSummary: string | null = null;
  let verdict: ScoreVerdict | null = null;

  if (row.alert_context_json) {
    try {
      const alerts = JSON.parse(row.alert_context_json) as WazuhAlert[];
      alertSummary = alerts[0]?.rule?.description ?? null;
    } catch {
      alertSummary = null;
    }
  }

  if (row.scorer_verdict_json) {
    try {
      const verdicts = JSON.parse(row.scorer_verdict_json) as (ScoreVerdict | null)[];
      verdict = verdicts[0] ?? null;
    } catch {
      verdict = null;
    }
  }

  return {
    id: row.id,
    createdAt: row.created_at,
    sessionId: row.session_id,
    alertSummary,
    verdict,
    status: row.status as InvestigationSummary['status'],
    model: row.model,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Creates a new investigation row before the first Claude API call, returning
 * its UUID v4 id (crypto.randomUUID() -- unguessable by construction, safe to
 * use directly as a permalink). system_prompt/user_message are scrubbed for
 * sk-ant-... patterns before insert.
 */
export function createInvestigation(params: CreateInvestigationParams): string {
  const db = getDb();
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  const alertContextJson = params.alertContext ? JSON.stringify(params.alertContext) : null;
  const scorerVerdictJson = params.scorerVerdicts ? JSON.stringify(params.scorerVerdicts) : null;
  const systemPrompt = scrubSecrets(params.systemPrompt);
  const userMessage = scrubSecrets(params.userMessage);

  db.query(
    `INSERT INTO investigations
       (id, created_at, session_id, alert_context_json, scorer_verdict_json, model, system_prompt, user_message, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running')`
  ).run(id, createdAt, params.sessionId, alertContextJson, scorerVerdictJson, params.model, systemPrompt, userMessage);

  return id;
}

/**
 * Appends one ordered replay step (llm / tool_call / tool_result) to an
 * investigation. `seq` is assigned by the caller (pai-client.ts) as it walks
 * the tool-use loop; ORDER BY seq reconstructs the exact sequence Claude saw.
 */
export function appendStep(
  investigationId: string,
  seq: number,
  type: StepType,
  payload: LlmStepPayload | ToolCallStepPayload | ToolResultStepPayload
): void {
  if (type !== 'llm' && type !== 'tool_call' && type !== 'tool_result') {
    throw new Error(`appendStep: invalid step type '${type}' (expected 'llm' | 'tool_call' | 'tool_result')`);
  }

  const db = getDb();
  const createdAt = new Date().toISOString();

  db.query(
    `INSERT INTO investigation_steps (investigation_id, seq, type, payload_json, created_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run(investigationId, seq, type, JSON.stringify(payload), createdAt);
}

/**
 * Marks an investigation as completed/error and records final analysis +
 * token/duration totals. final_analysis is scrubbed the same way as
 * system_prompt/user_message. A no-op (does not throw) if the id doesn't exist.
 */
export function finalizeInvestigation(investigationId: string, params: FinalizeInvestigationParams): void {
  const db = getDb();
  const finalAnalysis = scrubSecrets(params.finalAnalysis);

  db.query(
    `UPDATE investigations
        SET status = ?, final_analysis = ?, input_tokens = ?, output_tokens = ?, duration_ms = ?
      WHERE id = ?`
  ).run(params.status, finalAnalysis, params.inputTokens, params.outputTokens, params.durationMs, investigationId);
}

/**
 * Lists investigations most-recent-first for GET /ledger. Cheap -- no join
 * against investigation_steps (matches the two-table split rationale in
 * docs/architecture-scorer-ledger.md section 3). `limit` defaults to 50 and is always clamped to
 * the inclusive range [1, 200] regardless of what's requested.
 */
export function listInvestigations(limit = 50): InvestigationSummary[] {
  const db = getDb();
  const cappedLimit = Math.min(Math.max(1, Math.trunc(limit) || 50), 200);

  const rows = db
    .query(
      `SELECT id, created_at, session_id, alert_context_json, scorer_verdict_json, model,
              system_prompt, user_message, final_analysis, input_tokens, output_tokens, duration_ms, status
         FROM investigations
        ORDER BY created_at DESC
        LIMIT ?`
    )
    .all(cappedLimit) as InvestigationRow[];

  return rows.map(rowToSummary);
}

/**
 * Fetches the full replay detail for one investigation, including its ordered
 * steps. Validates `id` against a UUID regex BEFORE touching SQL -- malformed
 * ids return null immediately without a query ever running (defense in depth
 * per docs/architecture-scorer-ledger.md section 9, independent of any route-level regex check).
 * Returns null if the id is well-formed but no such investigation exists.
 */
export function getInvestigation(id: string): InvestigationDetail | null {
  if (typeof id !== 'string' || !UUID_RE.test(id)) {
    return null;
  }

  const db = getDb();

  const row = db
    .query(
      `SELECT id, created_at, session_id, alert_context_json, scorer_verdict_json, model,
              system_prompt, user_message, final_analysis, input_tokens, output_tokens, duration_ms, status
         FROM investigations
        WHERE id = ?`
    )
    .get(id) as InvestigationRow | null;

  if (!row) {
    return null;
  }

  const stepRows = db
    .query(
      `SELECT id, investigation_id, seq, type, payload_json, created_at
         FROM investigation_steps
        WHERE investigation_id = ?
        ORDER BY seq ASC`
    )
    .all(id) as StepRow[];

  const steps: InvestigationStep[] = stepRows.map((r) => ({
    id: r.id,
    investigationId: r.investigation_id,
    seq: r.seq,
    type: r.type as StepType,
    payload: JSON.parse(r.payload_json),
    createdAt: r.created_at,
  }));

  let alertContext: WazuhAlert[] | null = null;
  let verdicts: (ScoreVerdict | null)[] | null = null;

  if (row.alert_context_json) {
    try {
      alertContext = JSON.parse(row.alert_context_json) as WazuhAlert[];
    } catch {
      alertContext = null;
    }
  }

  if (row.scorer_verdict_json) {
    try {
      verdicts = JSON.parse(row.scorer_verdict_json) as (ScoreVerdict | null)[];
    } catch {
      verdicts = null;
    }
  }

  const summary = rowToSummary(row);

  return {
    ...summary,
    alertContext,
    verdicts,
    systemPrompt: row.system_prompt,
    userMessage: row.user_message,
    finalAnalysis: row.final_analysis,
    inputTokens: row.input_tokens,
    outputTokens: row.output_tokens,
    durationMs: row.duration_ms,
    steps,
  };
}
