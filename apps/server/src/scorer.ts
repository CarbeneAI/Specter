/**
 * Specter - Deterministic Alert Scorer
 *
 * Pure, dependency-free, zero-API-key pre-triage. Every ingested WazuhAlert gets scored
 * (0-100, banded critical->noise) by `LocalDeterministicScorer` BEFORE Claude is ever
 * invoked -- this file never reads ANTHROPIC_API_KEY or any other secret, and it never
 * makes a network call. That's what lets it run even when the AI chat panel is
 * unconfigured (see docs/architecture-scorer-ledger.md section 1, "Fail-open" / no-key degradation).
 *
 * ---------------------------------------------------------------------------------
 * THE SEAM -- read this before touching anything below
 * ---------------------------------------------------------------------------------
 * `getScoringBackend()` / `registerScoringBackend()` are the ONLY seam an alternative
 * scoring backend needs to touch. This file intentionally contains NO cross-instance
 * aggregation math, NO reputation model, and NO shared schema -- only
 * `LocalDeterministicScorer`, which scores one alert, alone, from data already sitting
 * in-process. That is a deliberate boundary, not an oversight: single-host scoring is a
 * different problem from combining signal across many installs, and mixing them makes
 * both harder to reason about and to teach.
 *
 * To swap in your own: implement the `ScoringBackend` interface below and call
 * `registerScoringBackend()` once at startup. Every other call site in this codebase
 * (alert-ingest.ts, index.ts, etc.) keeps calling `getScoringBackend().score(...)` /
 * `scoreAndAttach(...)` completely unaware anything changed.
 *
 * The architectural case for pushing this decision all the way onto the endpoint is
 * published, unencumbered, at https://github.com/CarbeneAI/endpoint-mesh
 * ---------------------------------------------------------------------------------
 */

import type { WazuhAlert } from './types';

// ============================================================================
// 1. Types (docs/architecture-scorer-ledger.md section 4.1)
// ============================================================================

/** Alert bands, ordered most->least severe, plus 'noise' for alert-fatigue suppression candidates. */
export type ScoreBand = 'critical' | 'high' | 'medium' | 'low' | 'noise';

export interface ScoreVerdict {
  score: number; // 0-100, clamped
  band: ScoreBand;
  reasons: string[]; // human-readable, e.g. "rule level 12 (critical) (+90)"
  signals: Record<string, number>; // named signal -> point contribution, for transparency/teaching
  backend: string; // which backend produced this, e.g. 'local-deterministic'
}

export interface ScoringContext {
  windowMs: number; // frequency lookback window (informational, used in `reasons`)
  lookupFrequency?: (key: string) => number; // key = `${srcip}:${rule.id}`; caller injects the implementation
}

/**
 * The seam. An alternative backend implements this interface and calls
 * `registerScoringBackend()` before first use -- no other call site in this codebase
 * changes. See THE SEAM comment block at the top of this file.
 */
export interface ScoringBackend {
  name: string;
  score(alert: WazuhAlert, ctx: ScoringContext): Promise<ScoreVerdict>;
}

// ============================================================================
// 2. Constants -- SCORER_WEIGHTS, SCORE_BANDS, FREQUENCY_NOISE_THRESHOLD, SUPPRESSED_GROUPS
//
// This is the one place scoring math lives. Every number below is named and commented
// so a student reading this file (or a future maintainer tuning it) never has to go
// hunting for a magic number buried in a conditional.
// ============================================================================

/**
 * SCORER_WEIGHTS -- every point value `LocalDeterministicScorer` can award or deduct.
 * Kept as a single exported constant (per docs/architecture-scorer-ledger.md section 1's "teaching-legible"
 * goal) so the entire scoring model is readable and tunable from one spot.
 */
export const SCORER_WEIGHTS = {
  /**
   * Base points awarded purely from Wazuh's own `rule.level` (0-15), bucketed using the
   * same critical/high/medium/low thresholds already used elsewhere in Specter (see
   * `types.ts` -> `getSeverityLevel`). This is intentionally the dominant signal --
   * Wazuh's decoder/rule authors already spent years tuning rule severity, so we start
   * there and layer cheap, deterministic adjustments on top rather than re-deriving
   * severity from scratch.
   *
   * The four values are spaced so that, with no other signal firing, each severity
   * bucket lands squarely in its matching ScoreBand (see SCORE_BANDS below) -- e.g. a
   * bare rule.level 7 alert (severity 'high', +65) bands as 'high', not 'medium'.
   */
  ruleLevelBase: {
    critical: 90, // rule.level >= 12
    high: 65, // rule.level 7-11
    medium: 35, // rule.level 3-6
    low: 10, // rule.level 0-2
  },
  /**
   * MITRE ATT&CK presence signal: an alert whose rule ships mapped tactic/technique data
   * has already been analyst-vetted against a real adversary behavior, not just a
   * generic decoder match. Presence upweights; absence is a strict no-op (never
   * downweighted) -- most Wazuh rules don't carry MITRE mapping at all, and that must
   * not read as "less suspicious," just "less enriched."
   */
  mitrePresence: 10,
  /**
   * Frequency downweight: applied when the same srcip+rule combination has fired more
   * than FREQUENCY_NOISE_THRESHOLD times inside the caller-supplied lookback window --
   * that smells like alert fatigue (a noisy scanner, a flapping health check) rather
   * than a fresh incident. This is a flat penalty, not multiplied by count, so one very
   * noisy source can't swing the score further than a merely-noisy one -- keeps the
   * signal legible and bounded.
   *
   * Scope: this signal ONLY fires when the alert's base rule-level severity is already
   * 'low' or 'medium'. A repeating 'critical' or 'high' alert (e.g. a brute force still
   * in progress) is an active incident, not noise, and frequency alone must never
   * demote it -- see Signal 3 below for the gating check.
   */
  frequencyDownweight: -40,
  /**
   * Suppressed-group downweight: fires when `rule.groups` intersects SUPPRESSED_GROUPS
   * (below), i.e. categories already decided to be routine/expected noise. Flat penalty,
   * same reasoning as the frequency signal.
   */
  suppressedGroupDownweight: -20,
} as const;

/**
 * SCORE_BANDS -- score-to-band boundaries, checked in order (highest `min` first). The
 * first entry whose `min` the final clamped score satisfies wins. 'noise' has no floor
 * (min: 0) so it always matches as the fallback for anything that didn't clear 'low'.
 */
export const SCORE_BANDS: ReadonlyArray<{ band: ScoreBand; min: number }> = [
  { band: 'critical', min: 80 },
  { band: 'high', min: 55 },
  { band: 'medium', min: 25 },
  { band: 'low', min: 10 },
  { band: 'noise', min: 0 },
];

/**
 * FREQUENCY_NOISE_THRESHOLD -- occurrence count (within `ctx.windowMs`) above which the
 * frequency-downweight signal fires. Tuned as "more than roughly once an hour over a
 * 24h window" for the default window used by alert-ingest.ts; callers with a different
 * `windowMs` should treat this threshold as scaled to whatever window they inject.
 */
export const FREQUENCY_NOISE_THRESHOLD = 20;

/**
 * SUPPRESSED_GROUPS -- Wazuh `rule.groups` values that the team has already decided are
 * routine/expected and shouldn't compete for analyst attention at full severity. This is
 * a starting list, not exhaustive -- teams are expected to tune it for their environment.
 */
export const SUPPRESSED_GROUPS: ReadonlyArray<string> = [
  'authentication_success', // successful logins are expected noise, not incidents
  'web_scan', // routine vulnerability/recon scanning, already tracked separately
  'firewall_drop', // default-deny drops are expected baseline traffic, not signal
];

// ============================================================================
// 3. Helpers
// ============================================================================

function formatSigned(n: number): string {
  return n >= 0 ? `+${n}` : `${n}`;
}

/** Maps a raw Wazuh rule.level (0-15) to the severity bucket used by SCORER_WEIGHTS.ruleLevelBase. */
function severityBucket(level: number): keyof typeof SCORER_WEIGHTS.ruleLevelBase {
  if (level >= 12) return 'critical';
  if (level >= 7) return 'high';
  if (level >= 3) return 'medium';
  return 'low';
}

/** Walks SCORE_BANDS (already ordered highest-min-first) and returns the first match. */
function computeBand(score: number): ScoreBand {
  for (const entry of SCORE_BANDS) {
    if (score >= entry.min) return entry.band;
  }
  // Unreachable given SCORE_BANDS always ends with a min: 0 entry, but keeps the
  // function total in case that invariant is ever broken.
  return 'noise';
}

// ============================================================================
// 4. LocalDeterministicScorer
//
// Pure and synchronous by design -- no I/O, no env reads, no randomness. Given the same
// WazuhAlert and the same ScoringContext (including whatever lookupFrequency returns),
// it always returns byte-for-byte the same ScoreVerdict. That determinism is what the
// "no-key degradation" and "scorer determinism" acceptance criteria in
// docs/architecture-scorer-ledger.md section 10 depend on.
// ============================================================================

export const LocalDeterministicScorer = {
  score(alert: WazuhAlert, ctx: ScoringContext): ScoreVerdict {
    const reasons: string[] = [];
    const signals: Record<string, number> = {};
    let total = 0;

    // --- Signal 1: rule-level base ---
    const level = alert.rule.level;
    const severity = severityBucket(level);
    const basePoints = SCORER_WEIGHTS.ruleLevelBase[severity];
    signals.ruleLevelBase = basePoints;
    reasons.push(`rule level ${level} (${severity}) (${formatSigned(basePoints)})`);
    total += basePoints;

    // --- Signal 2: MITRE ATT&CK presence (upweight only; absence is a no-op) ---
    const mitre = alert.rule.mitre;
    const hasMitre = !!mitre && ((mitre.id?.length ?? 0) > 0 || (mitre.technique?.length ?? 0) > 0 || (mitre.tactic?.length ?? 0) > 0);
    if (hasMitre) {
      signals.mitrePresence = SCORER_WEIGHTS.mitrePresence;
      reasons.push(`MITRE ATT&CK mapping present (${formatSigned(SCORER_WEIGHTS.mitrePresence)})`);
      total += SCORER_WEIGHTS.mitrePresence;
    }

    // --- Signal 3: frequency downweight — low/medium base severity ONLY. A repeating
    // critical/high alert is still an active incident (e.g. in-progress brute force),
    // not noise, so we never demote it on frequency alone.
    if (typeof ctx.lookupFrequency === 'function' && (severity === 'low' || severity === 'medium')) {
      const key = `${alert.srcip ?? ''}:${alert.rule.id}`;
      let count: number | undefined;
      try {
        count = ctx.lookupFrequency(key);
      } catch {
        // A misbehaving injected lookup must never crash scoring -- skip the signal.
        count = undefined;
      }
      if (typeof count === 'number' && Number.isFinite(count) && count > FREQUENCY_NOISE_THRESHOLD) {
        signals.frequency = SCORER_WEIGHTS.frequencyDownweight;
        reasons.push(
          `seen ${count}x for ${key} within ${ctx.windowMs}ms window, exceeds noise threshold ${FREQUENCY_NOISE_THRESHOLD} (${formatSigned(SCORER_WEIGHTS.frequencyDownweight)})`
        );
        total += SCORER_WEIGHTS.frequencyDownweight;
      }
    }

    // --- Signal 4: suppressed-group downweight (fires only on intersection) ---
    const groups = alert.rule.groups ?? [];
    const suppressedHit = groups.find((g) => SUPPRESSED_GROUPS.includes(g));
    if (suppressedHit) {
      signals.suppressedGroup = SCORER_WEIGHTS.suppressedGroupDownweight;
      reasons.push(`rule group '${suppressedHit}' is in the suppressed-noise list (${formatSigned(SCORER_WEIGHTS.suppressedGroupDownweight)})`);
      total += SCORER_WEIGHTS.suppressedGroupDownweight;
    }

    // --- Clamp + band ---
    const score = Math.max(0, Math.min(100, total));
    const band = computeBand(score);

    return { score, band, reasons, signals, backend: 'local-deterministic' };
  },
};

// ============================================================================
// 5. The seam: getScoringBackend() / registerScoringBackend()
// ============================================================================

/** Adapter that satisfies ScoringBackend using the pure, synchronous LocalDeterministicScorer. */
const localBackend: ScoringBackend = {
  name: 'local-deterministic',
  async score(alert: WazuhAlert, ctx: ScoringContext): Promise<ScoreVerdict> {
    return LocalDeterministicScorer.score(alert, ctx);
  },
};

let activeBackend: ScoringBackend = localBackend;

/** Returns the currently-registered ScoringBackend singleton (default: local-deterministic). */
export function getScoringBackend(): ScoringBackend {
  return activeBackend;
}

/**
 * Swaps the active ScoringBackend. This is the ONLY function an alternative backend
 * needs to call, once, at startup -- see THE SEAM comment at the top of this file.
 * No other call site in this codebase needs to change.
 */
export function registerScoringBackend(backend: ScoringBackend): void {
  activeBackend = backend;
}

// ============================================================================
// 6. scoreAndAttach() -- the helper alert-ingest.ts calls at every ingestion point
// ============================================================================

/**
 * Scores every alert via the currently-registered backend and returns new alert objects
 * with `.verdict` attached (non-mutating: each input alert is shallow-copied, so callers
 * holding a reference to the original object never see it change out from under them).
 */
export async function scoreAndAttach(alerts: WazuhAlert[], ctx: ScoringContext): Promise<WazuhAlert[]> {
  const backend = getScoringBackend();
  return Promise.all(
    alerts.map(async (alert) => {
      const verdict = await backend.score(alert, ctx);
      return { ...alert, verdict };
    })
  );
}
