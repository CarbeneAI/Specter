/**
 * Specter - Investigation Ledger tests
 *
 * Covers docs/architecture-scorer-ledger.md section 10's ledger.test.ts acceptance list:
 *  - full round-trip (createInvestigation -> appendStep xN -> finalizeInvestigation
 *    -> getInvestigation), steps returned in seq order
 *  - listInvestigations(limit): most-recent-first, respects limit, caps at 200
 *  - malformed id passed to getInvestigation returns null without throwing or
 *    touching SQLite
 *  - resolveDbPath(): rejects a NUL byte, creates parent directories, reuses the
 *    same connection across calls with the same LEDGER_DB_PATH
 *  - parameterized-query safety: a rule.description containing a SQL injection
 *    payload round-trips as inert text
 *
 * SCOPE NOTE: share-token functionality (createShareToken/resolveShareToken) is
 * deferred/out of scope for this build -- the share_tokens table does not exist
 * and is intentionally not tested here.
 *
 * Each test gets its own temp LEDGER_DB_PATH (via beforeEach), cleaned up in
 * afterEach, so tests never share ledger state or leave files behind.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { WazuhAlert } from './types';
import {
  appendStep,
  createInvestigation,
  finalizeInvestigation,
  getDb,
  getInvestigation,
  listInvestigations,
  resolveDbPath,
} from './ledger';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function makeAlert(description: string): WazuhAlert {
  return {
    timestamp: new Date().toISOString(),
    rule: { level: 10, description, id: '5710' },
    agent: { id: '001', name: 'test-agent' },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'specter-ledger-'));
  process.env.LEDGER_DB_PATH = join(tmpDir, 'ledger.sqlite');
});

afterEach(() => {
  delete process.env.LEDGER_DB_PATH;
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('createInvestigation -> appendStep -> finalizeInvestigation -> getInvestigation', () => {
  test('round-trips every field, steps in seq order', () => {
    const alert = makeAlert('Multiple authentication failures');

    const id = createInvestigation({
      sessionId: 'session-abc',
      alertContext: [alert],
      scorerVerdicts: [null],
      model: 'claude-sonnet-4-20250514',
      systemPrompt: 'You are a security analyst.',
      userMessage: 'What happened here?',
    });

    expect(UUID_RE.test(id)).toBe(true);

    appendStep(id, 0, 'llm', {
      role: 'assistant',
      content: [{ type: 'text', text: 'Let me check.' }],
      stopReason: 'tool_use',
      usage: { input_tokens: 10, output_tokens: 5 },
    });
    appendStep(id, 1, 'tool_call', {
      toolUseId: 'tu_1',
      name: 'search_wazuh_alerts',
      input: { query: 'auth failures', limit: 10 },
    });
    appendStep(id, 2, 'tool_result', {
      toolUseId: 'tu_1',
      resultText: 'Found 3 related alerts.',
    });

    finalizeInvestigation(id, {
      status: 'completed',
      finalAnalysis: 'This looks like a brute-force attempt.',
      inputTokens: 120,
      outputTokens: 48,
      durationMs: 2345,
    });

    const detail = getInvestigation(id);
    expect(detail).not.toBeNull();
    expect(detail!.id).toBe(id);
    expect(detail!.sessionId).toBe('session-abc');
    expect(detail!.model).toBe('claude-sonnet-4-20250514');
    expect(detail!.systemPrompt).toBe('You are a security analyst.');
    expect(detail!.userMessage).toBe('What happened here?');
    expect(detail!.status).toBe('completed');
    expect(detail!.finalAnalysis).toBe('This looks like a brute-force attempt.');
    expect(detail!.inputTokens).toBe(120);
    expect(detail!.outputTokens).toBe(48);
    expect(detail!.durationMs).toBe(2345);
    expect(detail!.alertContext).toEqual([alert]);
    expect(detail!.verdicts).toEqual([null]);
    expect(detail!.alertSummary).toBe('Multiple authentication failures');

    expect(detail!.steps).toHaveLength(3);
    expect(detail!.steps.map((s) => s.seq)).toEqual([0, 1, 2]);
    expect(detail!.steps.map((s) => s.type)).toEqual(['llm', 'tool_call', 'tool_result']);
    expect((detail!.steps[1].payload as any).name).toBe('search_wazuh_alerts');
    expect((detail!.steps[2].payload as any).resultText).toBe('Found 3 related alerts.');
    for (const step of detail!.steps) {
      expect(step.investigationId).toBe(id);
    }
  });

  test('secrets in system_prompt/user_message/final_analysis are redacted before storage', () => {
    const id = createInvestigation({
      sessionId: 'session-secret',
      alertContext: null,
      scorerVerdicts: null,
      model: 'claude-sonnet-4-20250514',
      systemPrompt: 'Key is sk-ant-abc123XYZ789 do not leak',
      userMessage: 'here is my key sk-ant-def456UVW000',
    });

    finalizeInvestigation(id, {
      status: 'completed',
      finalAnalysis: 'analysis mentions sk-ant-ghi789RST111 too',
      inputTokens: 1,
      outputTokens: 1,
      durationMs: 1,
    });

    const detail = getInvestigation(id);
    expect(detail!.systemPrompt).toBe('Key is [redacted] do not leak');
    expect(detail!.userMessage).toBe('here is my key [redacted]');
    expect(detail!.finalAnalysis).toBe('analysis mentions [redacted] too');
  });

  test('finalizeInvestigation on a non-existent id is a no-op, does not throw', () => {
    expect(() =>
      finalizeInvestigation('00000000-0000-4000-8000-000000000000', {
        status: 'error',
        finalAnalysis: null,
        inputTokens: null,
        outputTokens: null,
        durationMs: null,
      })
    ).not.toThrow();
  });
});

describe('listInvestigations', () => {
  test('returns most-recent-first, respects limit, caps at 200', async () => {
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const id = createInvestigation({
        sessionId: `session-${i}`,
        alertContext: null,
        scorerVerdicts: null,
        model: 'claude-sonnet-4-20250514',
        systemPrompt: 'p',
        userMessage: 'u',
      });
      ids.push(id);
      // ensure distinct created_at timestamps so recency ordering is unambiguous
      await sleep(5);
    }

    const all = listInvestigations(200);
    expect(all).toHaveLength(5);
    expect(all[0].id).toBe(ids[4]); // most recently created first
    expect(all[4].id).toBe(ids[0]); // oldest last

    const limited = listInvestigations(2);
    expect(limited).toHaveLength(2);
    expect(limited[0].id).toBe(ids[4]);
    expect(limited[1].id).toBe(ids[3]);

    // requesting far above 200 must not throw and must still be capped
    const overRequested = listInvestigations(10_000);
    expect(overRequested.length).toBeLessThanOrEqual(200);
    expect(overRequested).toHaveLength(5); // only 5 rows exist, well under the cap

    const defaultLimit = listInvestigations();
    expect(defaultLimit).toHaveLength(5);
  });
});

describe('getInvestigation malformed-id guard', () => {
  test('returns null for non-UUID-shaped ids without throwing', () => {
    expect(getInvestigation('not-a-uuid')).toBeNull();
    expect(getInvestigation('')).toBeNull();
    expect(getInvestigation("1'; DROP TABLE investigations; --")).toBeNull();
    expect(getInvestigation('00000000-0000-0000-0000-00000000000')).toBeNull(); // one char short
  });

  test('never touches SQLite for a malformed id (proven via a poisoned LEDGER_DB_PATH)', () => {
    const original = process.env.LEDGER_DB_PATH;
    // A NUL byte makes resolveDbPath()/getDb() throw if they're ever reached.
    // If getInvestigation's UUID guard didn't short-circuit before touching
    // SQLite, this would throw instead of returning null.
    process.env.LEDGER_DB_PATH = 'poisoned\0path';
    try {
      expect(() => getInvestigation('not-a-uuid')).not.toThrow();
      expect(getInvestigation('not-a-uuid')).toBeNull();
    } finally {
      process.env.LEDGER_DB_PATH = original;
    }
  });

  test('well-formed but non-existent UUID returns null', () => {
    expect(getInvestigation('11111111-1111-4111-8111-111111111111')).toBeNull();
  });
});

describe('resolveDbPath / getDb', () => {
  test('rejects a path containing a NUL byte', () => {
    const original = process.env.LEDGER_DB_PATH;
    process.env.LEDGER_DB_PATH = 'bad\0path/ledger.sqlite';
    try {
      expect(() => resolveDbPath()).toThrow();
    } finally {
      process.env.LEDGER_DB_PATH = original;
    }
  });

  test('creates parent directories that do not yet exist', () => {
    const nested = join(tmpDir, 'a', 'b', 'c', 'ledger.sqlite');
    process.env.LEDGER_DB_PATH = nested;
    expect(existsSync(dirname(nested))).toBe(false);
    const resolved = resolveDbPath();
    expect(existsSync(dirname(resolved))).toBe(true);
  });

  test('two calls with the same LEDGER_DB_PATH reuse the same connection', () => {
    const db1 = getDb();
    const db2 = getDb();
    expect(db1).toBe(db2);
    // sanity: connection is actually usable (schema was applied)
    const row = db1
      .query("SELECT name FROM sqlite_master WHERE type='table' AND name='investigations'")
      .get();
    expect(row).not.toBeNull();
  });
});

describe('parameterized-query safety (SQLi round-trip)', () => {
  test("a rule.description containing '; DROP TABLE investigations; --' round-trips as inert text", () => {
    const payload = "'; DROP TABLE investigations; --";
    const alert = makeAlert(payload);

    const id = createInvestigation({
      sessionId: 'sqli-test',
      alertContext: [alert],
      scorerVerdicts: [null],
      model: 'claude-sonnet-4-20250514',
      systemPrompt: 'p',
      userMessage: 'u',
    });

    // If the payload were ever concatenated into SQL rather than bound as a
    // parameter, this would have dropped the investigations table.
    const detail = getInvestigation(id);
    expect(detail).not.toBeNull();
    expect(detail!.alertContext![0].rule.description).toBe(payload);
    expect(detail!.alertSummary).toBe(payload);

    // Table must still exist and be queryable -- proves parameterization, not
    // sanitization, is what kept this inert.
    expect(() => listInvestigations()).not.toThrow();
    const rows = listInvestigations();
    expect(rows.some((r) => r.id === id)).toBe(true);
  });

  test('SQLi payload in system_prompt/user_message also round-trips inertly', () => {
    const payload = "x'; DELETE FROM investigation_steps; --";

    const id = createInvestigation({
      sessionId: 'sqli-test-2',
      alertContext: null,
      scorerVerdicts: null,
      model: 'm',
      systemPrompt: payload,
      userMessage: payload,
    });

    appendStep(id, 0, 'llm', {
      role: 'assistant',
      content: [{ type: 'text', text: 'ok' }],
      stopReason: 'end_turn',
    });

    const detail = getInvestigation(id);
    expect(detail!.systemPrompt).toBe(payload);
    expect(detail!.userMessage).toBe(payload);
    expect(detail!.steps).toHaveLength(1); // not deleted by the injected payload
  });
});
