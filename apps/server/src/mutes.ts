/**
 * Specter - Alert Mutes
 *
 * A mute hides an alert in the Specter feed. It does NOT touch Suricata or the
 * Wazuh manager: the alert is still ingested, still scored, still counted, and
 * still searchable for hunting. Only the rendering is suppressed.
 *
 * This is deliberately distinct from suricata-suppression.ts, which disables the
 * signature upstream (SCP disable.conf + suricata-update, or level="0" in
 * local_rules.xml + a manager restart). Upstream suppression destroys the data
 * and needs an SSH grant into the sensor and the manager. Muting needs neither,
 * and is reversible in one click.
 *
 * KEY: a mute matches on `rule_id` + `srcip`. Muting "ET INFO Telegram in TLS SNI
 * from 192.168.2.200" does not mute the same signature from a server that has no
 * business talking to Telegram. `srcip = '*'` is an explicit rule-wide wildcard;
 * `srcip = ''` matches only alerts that carry no source IP at all.
 *
 * EXPIRY: mutes are time-boxed (default 30 days). An expired mute stops matching
 * immediately and resurfaces the alerts for review. Expired rows are kept, not
 * deleted, so the history of "what did I mute and why" survives. Pass
 * ttlDays = 0 for a mute that never expires.
 *
 * SECURITY: parameterized SQL only -- every query uses bun:sqlite `?` positional
 * placeholders. The sole template string is the static SCHEMA_SQL DDL, which
 * interpolates nothing. Inputs are validated before any SQL runs.
 */

import { Database } from 'bun:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { WazuhAlert } from './types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Mute {
  id: number;
  ruleId: string;
  /** Source IP this mute is scoped to. '*' = every source. '' = alerts with no srcip. */
  srcip: string;
  /** Rule description captured at mute time, so the list is readable later. */
  description: string;
  reason: string;
  createdAt: string;
  /** ISO timestamp, or null for a mute that never expires. */
  expiresAt: string | null;
  createdBy: string;
}

export interface CreateMuteParams {
  ruleId: string;
  srcip?: string;
  description?: string;
  reason?: string;
  /** Days until the mute lapses. Default 30. 0 means never expire. */
  ttlDays?: number;
  createdBy?: string;
}

interface MuteRow {
  id: number;
  rule_id: string;
  srcip: string;
  description: string;
  reason: string;
  created_at: string;
  expires_at: string | null;
  created_by: string;
}

/** Default lifetime of a mute, in days. */
export const DEFAULT_TTL_DAYS = 30;

/** Wildcard srcip value meaning "this rule from any source". */
export const SRCIP_ANY = '*';

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS alert_mutes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id     TEXT NOT NULL,
  srcip       TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  reason      TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  expires_at  TEXT,
  created_by  TEXT NOT NULL DEFAULT 'specter'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mutes_key
  ON alert_mutes(rule_id, srcip);

CREATE INDEX IF NOT EXISTS idx_mutes_expiry
  ON alert_mutes(expires_at);
`;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Wazuh rule IDs and Suricata SIDs are numeric strings. */
const RULE_ID_RE = /^\d{1,12}$/;

/**
 * Permissive IP-ish check: IPv4 dotted quad, IPv6 hex/colon form, the '*'
 * wildcard, or empty. Deliberately not a full RFC validator -- the point is to
 * reject junk (and anything with quotes, spaces, or control characters) before
 * it becomes a stored mute key, not to be an address parser.
 */
const SRCIP_RE = /^(\*|[0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F:]{2,45})?$/;

export function isValidRuleId(value: string): boolean {
  return RULE_ID_RE.test(value);
}

export function isValidSrcip(value: string): boolean {
  return SRCIP_RE.test(value);
}

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

let dbInstance: Database | null = null;
let dbInstancePath: string | null = null;

/**
 * Resolves MUTES_DB_PATH (default './data/mutes.sqlite') to an absolute path.
 * Kept in a separate file from the investigation ledger so a mute write can
 * never contend with, or corrupt, the audit log.
 */
export function resolveMutesDbPath(): string {
  const raw = process.env.MUTES_DB_PATH ?? './data/mutes.sqlite';
  if (raw.includes('\0')) {
    throw new Error('MUTES_DB_PATH must not contain a NUL byte');
  }
  const absolute = resolve(raw);
  mkdirSync(dirname(absolute), { recursive: true });
  return absolute;
}

export function getMutesDb(): Database {
  const path = resolveMutesDbPath();
  if (dbInstance && dbInstancePath === path) return dbInstance;
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // best effort; never block opening the new connection
    }
  }
  const db = new Database(path, { create: true });
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec(SCHEMA_SQL);
  dbInstance = db;
  dbInstancePath = path;
  return db;
}

/** Test hook: drop the cached connection so the next call reopens from env. */
export function resetMutesDb(): void {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // ignore
    }
  }
  dbInstance = null;
  dbInstancePath = null;
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

function rowToMute(row: MuteRow): Mute {
  return {
    id: row.id,
    ruleId: row.rule_id,
    srcip: row.srcip,
    description: row.description,
    reason: row.reason,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    createdBy: row.created_by,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create (or refresh) a mute. Re-muting an existing rule+srcip pair updates the
 * reason and pushes the expiry out rather than erroring -- "mute this again for
 * another 30 days" is the common case, and a duplicate-key error would be a
 * dead end in the UI.
 */
export function createMute(params: CreateMuteParams): { success: boolean; mute?: Mute; error?: string } {
  const ruleId = String(params.ruleId ?? '').trim();
  const srcip = String(params.srcip ?? '').trim();

  if (!isValidRuleId(ruleId)) {
    return { success: false, error: 'Invalid rule ID - must be numeric' };
  }
  if (!isValidSrcip(srcip)) {
    return { success: false, error: 'Invalid source IP' };
  }

  const ttlDaysRaw = params.ttlDays ?? DEFAULT_TTL_DAYS;
  const ttlDays = Number.isFinite(ttlDaysRaw) ? Math.max(0, Math.floor(ttlDaysRaw)) : DEFAULT_TTL_DAYS;

  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = ttlDays === 0
    ? null
    : new Date(now.getTime() + ttlDays * 24 * 60 * 60 * 1000).toISOString();

  const db = getMutesDb();
  db.query(
    `INSERT INTO alert_mutes (rule_id, srcip, description, reason, created_at, expires_at, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(rule_id, srcip) DO UPDATE SET
       description = excluded.description,
       reason      = excluded.reason,
       created_at  = excluded.created_at,
       expires_at  = excluded.expires_at,
       created_by  = excluded.created_by`
  ).run(
    ruleId,
    srcip,
    String(params.description ?? '').slice(0, 500),
    String(params.reason ?? '').slice(0, 500),
    createdAt,
    expiresAt,
    String(params.createdBy ?? 'specter').slice(0, 200),
  );

  const row = db.query('SELECT * FROM alert_mutes WHERE rule_id = ? AND srcip = ?')
    .get(ruleId, srcip) as MuteRow | null;

  return row ? { success: true, mute: rowToMute(row) } : { success: false, error: 'Mute was not persisted' };
}

/** Remove a mute by its rule+srcip key. */
export function deleteMute(ruleId: string, srcip: string): { success: boolean; error?: string } {
  const id = String(ruleId ?? '').trim();
  const ip = String(srcip ?? '').trim();
  if (!isValidRuleId(id)) return { success: false, error: 'Invalid rule ID - must be numeric' };
  if (!isValidSrcip(ip)) return { success: false, error: 'Invalid source IP' };

  const db = getMutesDb();
  const before = (db.query('SELECT COUNT(*) AS n FROM alert_mutes WHERE rule_id = ? AND srcip = ?')
    .get(id, ip) as { n: number }).n;
  if (before === 0) return { success: false, error: 'No such mute' };

  db.query('DELETE FROM alert_mutes WHERE rule_id = ? AND srcip = ?').run(id, ip);
  return { success: true };
}

/**
 * List mutes. Expired ones are excluded unless includeExpired is set, so the
 * dashboard's "muted" list only ever shows what is actually hiding alerts.
 */
export function listMutes(includeExpired = false): Mute[] {
  const db = getMutesDb();
  const nowIso = new Date().toISOString();
  const rows = includeExpired
    ? db.query('SELECT * FROM alert_mutes ORDER BY created_at DESC').all() as MuteRow[]
    : db.query(
        'SELECT * FROM alert_mutes WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC'
      ).all(nowIso) as MuteRow[];
  return rows.map(rowToMute);
}

/**
 * The source IP Specter keys a mute on. Wazuh puts it in different places
 * depending on the decoder, so check the top-level field first, then Suricata's
 * nested EVE fields.
 */
export function alertSrcip(alert: WazuhAlert): string {
  const data = alert.data as Record<string, any> | undefined;
  return String(alert.srcip || data?.src_ip || data?.srcip || '');
}

/**
 * True when this alert is hidden by an active mute.
 *
 * A mute matches when the rule ID matches (either the Wazuh rule ID or the
 * Suricata signature ID -- muting from a Suricata row keys on the SID, which is
 * the stable identity of the signature) AND the srcip matches exactly, or the
 * mute is the '*' wildcard.
 */
export function isMuted(alert: WazuhAlert, mutes: Mute[], now: Date = new Date()): boolean {
  const nowMs = now.getTime();
  const wazuhRuleId = String(alert.rule?.id ?? '');
  const sid = (alert.data as Record<string, any> | undefined)?.alert?.signature_id;
  const suricataSid = sid === undefined || sid === null ? '' : String(sid);
  const ip = alertSrcip(alert);

  for (const mute of mutes) {
    if (mute.expiresAt && new Date(mute.expiresAt).getTime() <= nowMs) continue;
    if (mute.ruleId !== wazuhRuleId && mute.ruleId !== suricataSid) continue;
    if (mute.srcip !== SRCIP_ANY && mute.srcip !== ip) continue;
    return true;
  }
  return false;
}
