/**
 * Specter - Integration tests (HTTP layer)
 *
 * Covers the docs/architecture-scorer-ledger.md section 10 "Integration" acceptance list that unit tests in
 * scorer.test.ts / ledger.test.ts can't reach because they never exercise index.ts's
 * actual route wiring (Bun.serve, the /ledger/:id regex guard, the /chat handler's
 * error-shape contract):
 *
 *  - POST /chat with ANTHROPIC_API_KEY unset returns a clean `success:false` error and
 *    creates NO ledger row (pinned to the real behavior found in pai-client.ts: getApiKey()
 *    throws before createInvestigation() is ever called, so this is not a `status:'error'`
 *    row -- there is no row at all).
 *  - POST /alerts/ingest -> GET /alerts/scored returns a non-null `.verdict`, with
 *    ANTHROPIC_API_KEY unset for the whole suite.
 *  - GET /ledger/:id replays a real investigation's steps in seq order.
 *  - GET /ledger/not-a-uuid -> 404, never 500.
 *
 * DESIGN NOTES (read before touching this file):
 *
 * 1. `alert-ingest.ts` calls `process.exit(1)` at MODULE IMPORT TIME if
 *    WAZUH_DASHBOARD_URL / WAZUH_DASHBOARD_PASSWORD are unset. Importing `./index` (which
 *    imports alert-ingest.ts transitively) requires those env vars to be set to *something*
 *    before the import, even though nothing in this file ever talks to a real Wazuh server.
 *
 * 2. `pai-client.ts` reads `process.env.ANTHROPIC_API_KEY` into a module-level `const` at
 *    import time, not per-call. That means "key present" vs "key absent" is fixed for the
 *    lifetime of whichever process imports it first -- it cannot be toggled per-test against
 *    the same running server. This suite deliberately keeps ANTHROPIC_API_KEY UNSET for its
 *    entire lifetime (one Bun.serve instance, imported once in beforeAll) to cover the
 *    no-key-degradation acceptance criterion end-to-end over real HTTP.
 *
 * 3. Because the key stays unset for the whole suite, `sendChatMessage()` never reaches its
 *    `fetch('https://api.anthropic.com/...')` call (getApiKey() throws first) -- so there is
 *    nothing to mock for the /chat test. For the ledger-replay test, docs/architecture-scorer-ledger.md section
 *    10 explicitly allows "a real (OR SEEDED) investigation" -- this suite seeds one directly
 *    via ledger.ts's own createInvestigation/appendStep/finalizeInvestigation (imported
 *    normally, so it's the exact same module instance + LEDGER_DB_PATH the live server uses)
 *    rather than driving it through a mocked Anthropic call. A global fetch guard is still
 *    installed as defense-in-depth so that (a) alert-ingest.ts's immediate poll against the
 *    fake WAZUH_DASHBOARD_URL never makes a real network call, and (b) if any code path ever
 *    did reach the Anthropic endpoint, it would hit a stub, never the real API.
 *
 * 4. index.ts doesn't export its `server` (Bun.serve() return value) or the polling interval
 *    it starts, so this suite can't explicitly tear either down. Harmless for a `bun test`
 *    run -- the process exits once the run completes.
 *
 * SCOPE NOTE: share-token routes (/ledger/:id/share, /ledger/share/:token) are
 * intentionally deferred/out of scope for this build and are NOT tested here.
 */

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendStep, createInvestigation, finalizeInvestigation } from './ledger';

const ENV_KEYS = [
  'PORT',
  'LEDGER_DB_PATH',
  'WAZUH_DASHBOARD_URL',
  'WAZUH_DASHBOARD_USER',
  'WAZUH_DASHBOARD_PASSWORD',
  'ANTHROPIC_API_KEY',
  'WAZUH_PAI_API_KEY',
  // pai-client.ts's getApiKey() falls back to a key FILE when both env vars are
  // unset (default `~/.claude/.env`). On a developer machine that file exists and
  // would satisfy the lookup, so this suite would silently stop testing the no-key
  // path it exists to test. SPECTER_ENV_FILE is pointed at a nonexistent path below.
  // NOTE: redirecting HOME does not work here -- Bun's os.homedir() resolves via
  // getpwuid and ignores process.env.HOME.
  'SPECTER_ENV_FILE',
] as const;

let PORT: number;
let BASE_URL: string;
let tmpDir: string;
let originalFetch: typeof fetch;
const savedEnv: Partial<Record<(typeof ENV_KEYS)[number], string>> = {};

beforeAll(async () => {
  for (const k of ENV_KEYS) {
    const v = process.env[k];
    if (v !== undefined) savedEnv[k] = v;
  }

  PORT = 20000 + Math.floor(Math.random() * 5000);
  BASE_URL = `http://localhost:${PORT}`;
  tmpDir = mkdtempSync(join(tmpdir(), 'specter-integration-'));

  process.env.PORT = String(PORT);
  process.env.LEDGER_DB_PATH = join(tmpDir, 'ledger.sqlite');
  // Dummy but present -- only needed so alert-ingest.ts's module-load guard doesn't
  // process.exit(1). No real network call to this host should ever happen (see note 3).
  process.env.WAZUH_DASHBOARD_URL = 'https://wazuh.invalid.test';
  process.env.WAZUH_DASHBOARD_USER = 'admin';
  process.env.WAZUH_DASHBOARD_PASSWORD = 'test-password-not-real';
  // The whole point of this suite: prove the app boots and the relevant routes work
  // with no Anthropic key configured at all. Both env vars getApiKey() consults must
  // go, AND HOME must point somewhere without a .claude/.env, or the file fallback
  // supplies a real key and the no-key assertions pass vacuously.
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.WAZUH_PAI_API_KEY;
  process.env.SPECTER_ENV_FILE = join(tmpDir, 'no-such-key-file.env');

  originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith(BASE_URL)) {
      return originalFetch(input as any, init);
    }
    if (url.startsWith('https://api.anthropic.com')) {
      // Defense-in-depth only -- should never be exercised, because getApiKey()
      // throws before any fetch once both env vars are unset AND SPECTER_ENV_FILE
      // points at a nonexistent file. If this stub ever does answer, the no-key
      // setup has sprung a leak.
      return new Response(
        JSON.stringify({
          content: [{ type: 'text', text: 'stub' }],
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    // The fake Wazuh Dashboard URL -- stub an empty-hits response so alert-ingest.ts's
    // immediate poll-on-startup never makes a real network call in this test run.
    return new Response(JSON.stringify({ hits: { hits: [] } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as unknown as typeof fetch;

  await import('./index');

  // Bun.serve() binds synchronously, but poll /health defensively rather than assume.
  const deadline = Date.now() + 5000;
  let lastErr: unknown;
  for (;;) {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      if (res.ok) break;
    } catch (e) {
      lastErr = e;
    }
    if (Date.now() > deadline) {
      throw new Error(`Server never became healthy at ${BASE_URL}/health: ${String(lastErr)}`);
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}, 15000);

afterAll(() => {
  globalThis.fetch = originalFetch;
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k]!;
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('POST /chat with ANTHROPIC_API_KEY unset (no-key degradation, over real HTTP)', () => {
  test('returns a clean success:false error and creates no ledger row', async () => {
    const before = (await (await fetch(`${BASE_URL}/ledger?limit=200`)).json()) as {
      investigations: unknown[];
    };

    const res = await fetch(`${BASE_URL}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'What does this alert mean?' }),
    });

    // The route never sets a non-200 status for a handled sendChatMessage() failure --
    // pinning that here so a future change to error-status semantics is a visible diff.
    expect(res.status).toBe(200);

    const body = (await res.json()) as { success: boolean; error?: string; investigationId?: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('ANTHROPIC_API_KEY');
    expect(body.investigationId).toBeUndefined();

    const after = (await (await fetch(`${BASE_URL}/ledger?limit=200`)).json()) as {
      investigations: unknown[];
    };
    // Pinning the actual design: getApiKey() throws before createInvestigation() is ever
    // called, so no row is written at all (not a status:'error' row).
    expect(after.investigations.length).toBe(before.investigations.length);
  });
});

describe('POST /alerts/ingest -> GET /alerts/scored (no ANTHROPIC_API_KEY set)', () => {
  test('an ingested alert is retrievable via /alerts/scored with a non-null verdict', async () => {
    expect(process.env.ANTHROPIC_API_KEY).toBeUndefined();

    const marker = `integration-test-${Date.now()}`;
    const alert = {
      timestamp: new Date().toISOString(),
      rule: { level: 12, description: marker, id: '900001', groups: ['attack'] },
      agent: { id: '001', name: 'integration-agent' },
      srcip: '198.51.100.7',
    };

    const ingestRes = await fetch(`${BASE_URL}/alerts/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    });
    expect(ingestRes.status).toBe(200);
    const ingestBody = (await ingestRes.json()) as { success: boolean; count: number };
    expect(ingestBody.success).toBe(true);
    expect(ingestBody.count).toBe(1);

    const scoredRes = await fetch(`${BASE_URL}/alerts/scored?limit=500`);
    expect(scoredRes.status).toBe(200);
    const scored = (await scoredRes.json()) as Array<{
      rule: { description: string };
      verdict?: { band: string; backend: string; score: number };
    }>;

    const found = scored.find((a) => a.rule.description === marker);
    expect(found).toBeDefined();
    expect(found!.verdict).toBeDefined();
    expect(found!.verdict!.backend).toBe('local-deterministic');
    expect(found!.verdict!.band).toBe('critical'); // rule level 12, no downweight signals fired
    expect(typeof found!.verdict!.score).toBe('number');
  });
});

describe('GET /ledger/:id replay (seeded investigation -- see design note 3 above)', () => {
  test('replays a real ledger row\'s steps in seq order over HTTP', async () => {
    const id = createInvestigation({
      sessionId: 'integration-seed',
      alertContext: null,
      scorerVerdicts: null,
      model: 'test-model',
      systemPrompt: 'You are a test analyst.',
      userMessage: 'Seeded investigation for integration test.',
    });

    appendStep(id, 0, 'llm', {
      role: 'assistant',
      content: [{ type: 'text', text: 'thinking' }],
      stopReason: 'tool_use',
    });
    appendStep(id, 1, 'tool_call', {
      toolUseId: 'tu_1',
      name: 'search_wazuh_alerts',
      input: { query: 'test' },
    });
    appendStep(id, 2, 'tool_result', {
      toolUseId: 'tu_1',
      resultText: 'no related alerts',
    });

    finalizeInvestigation(id, {
      status: 'completed',
      finalAnalysis: 'Seeded final analysis.',
      inputTokens: 50,
      outputTokens: 20,
      durationMs: 500,
    });

    const res = await fetch(`${BASE_URL}/ledger/${id}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      investigation: {
        id: string;
        finalAnalysis: string | null;
        steps: Array<{ seq: number; type: string }>;
      };
    };

    expect(body.investigation.id).toBe(id);
    expect(body.investigation.finalAnalysis).toBe('Seeded final analysis.');
    expect(body.investigation.steps.map((s) => s.seq)).toEqual([0, 1, 2]);
    expect(body.investigation.steps.map((s) => s.type)).toEqual(['llm', 'tool_call', 'tool_result']);
  });

  test('also appears in GET /ledger (list)', async () => {
    const id = createInvestigation({
      sessionId: 'integration-list-check',
      alertContext: null,
      scorerVerdicts: null,
      model: 'test-model',
      systemPrompt: 'sys',
      userMessage: 'user',
    });

    const res = await fetch(`${BASE_URL}/ledger?limit=200`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { investigations: Array<{ id: string }> };
    expect(body.investigations.some((i) => i.id === id)).toBe(true);
  });
});

describe('GET /ledger/:id malformed id', () => {
  test('non-UUID path returns 404, not 500', async () => {
    const res = await fetch(`${BASE_URL}/ledger/not-a-uuid`);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('Not found');
  });

  test('a SQL-injection-shaped path segment also 404s cleanly, not 500', async () => {
    const res = await fetch(`${BASE_URL}/ledger/${encodeURIComponent("1'; DROP TABLE investigations; --")}`);
    expect(res.status).toBe(404);
  });
});
