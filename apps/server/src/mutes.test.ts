/**
 * Tests for apps/server/src/mutes.ts
 *
 * Each test runs against its own temp SQLite file so nothing leaks between
 * cases and nothing touches the real ./data/mutes.sqlite.
 */

import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createMute,
  deleteMute,
  listMutes,
  isMuted,
  alertSrcip,
  resetMutesDb,
  resolveMutesDbPath,
  isValidRuleId,
  isValidSrcip,
  SRCIP_ANY,
  DEFAULT_TTL_DAYS,
  type Mute,
} from './mutes';
import type { WazuhAlert } from './types';

let tmpDir: string;
let prevPath: string | undefined;

beforeEach(() => {
  prevPath = process.env.MUTES_DB_PATH;
  tmpDir = mkdtempSync(join(tmpdir(), 'specter-mutes-'));
  process.env.MUTES_DB_PATH = join(tmpDir, 'mutes.sqlite');
  resetMutesDb();
});

afterEach(() => {
  resetMutesDb();
  if (prevPath === undefined) delete process.env.MUTES_DB_PATH;
  else process.env.MUTES_DB_PATH = prevPath;
  rmSync(tmpDir, { recursive: true, force: true });
});

function alert(overrides: Partial<WazuhAlert> = {}): WazuhAlert {
  return {
    timestamp: new Date().toISOString(),
    rule: { level: 3, description: 'ET INFO Observed Telegram Domain in TLS SNI', id: '86601' },
    agent: { id: '001', name: 'Suricata' },
    ...overrides,
  } as WazuhAlert;
}

describe('validation', () => {
  test('accepts numeric rule ids, rejects everything else', () => {
    expect(isValidRuleId('86601')).toBe(true);
    expect(isValidRuleId('2027390')).toBe(true);
    expect(isValidRuleId('')).toBe(false);
    expect(isValidRuleId('86601; DROP TABLE alert_mutes')).toBe(false);
    expect(isValidRuleId('../../etc/passwd')).toBe(false);
  });

  test('accepts IPs, the wildcard and empty; rejects injection-ish junk', () => {
    expect(isValidSrcip('192.168.2.200')).toBe(true);
    expect(isValidSrcip('fdbb:adcf:2b84::1')).toBe(true);
    expect(isValidSrcip(SRCIP_ANY)).toBe(true);
    expect(isValidSrcip('')).toBe(true);
    expect(isValidSrcip("192.168.2.200' OR 1=1--")).toBe(false);
    expect(isValidSrcip('10.0.0.1 rm -rf /')).toBe(false);
  });
});

describe('createMute', () => {
  test('creates a mute with the 30 day default expiry', () => {
    const before = Date.now();
    const result = createMute({ ruleId: '86601', srcip: '192.168.2.200', reason: 'my phone' });
    expect(result.success).toBe(true);
    const mute = result.mute as Mute;
    expect(mute.ruleId).toBe('86601');
    expect(mute.srcip).toBe('192.168.2.200');
    expect(mute.reason).toBe('my phone');
    expect(mute.expiresAt).not.toBeNull();

    const ttlMs = new Date(mute.expiresAt as string).getTime() - before;
    const expected = DEFAULT_TTL_DAYS * 24 * 60 * 60 * 1000;
    // within a minute of the expected 30 days
    expect(Math.abs(ttlMs - expected)).toBeLessThan(60_000);
  });

  test('ttlDays = 0 means never expires', () => {
    const result = createMute({ ruleId: '86601', ttlDays: 0 });
    expect(result.success).toBe(true);
    expect((result.mute as Mute).expiresAt).toBeNull();
  });

  test('re-muting the same key refreshes instead of erroring', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200', reason: 'first' });
    const second = createMute({ ruleId: '86601', srcip: '192.168.2.200', reason: 'second' });
    expect(second.success).toBe(true);
    expect((second.mute as Mute).reason).toBe('second');
    expect(listMutes().length).toBe(1);
  });

  test('rejects a non-numeric rule id without writing', () => {
    const result = createMute({ ruleId: 'not-a-rule' });
    expect(result.success).toBe(false);
    expect(result.error).toContain('rule ID');
    expect(listMutes().length).toBe(0);
  });

  test('rejects a malformed srcip without writing', () => {
    const result = createMute({ ruleId: '86601', srcip: "1.2.3.4'; DELETE FROM alert_mutes--" });
    expect(result.success).toBe(false);
    expect(listMutes().length).toBe(0);
  });

  test('same rule from different sources are independent mutes', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200' });
    createMute({ ruleId: '86601', srcip: '192.168.2.92' });
    expect(listMutes().length).toBe(2);
  });
});

describe('deleteMute', () => {
  test('removes an existing mute', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200' });
    expect(deleteMute('86601', '192.168.2.200').success).toBe(true);
    expect(listMutes().length).toBe(0);
  });

  test('reports when there is nothing to delete', () => {
    const result = deleteMute('86601', '192.168.2.200');
    expect(result.success).toBe(false);
    expect(result.error).toBe('No such mute');
  });

  test('deleting one source does not affect another', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200' });
    createMute({ ruleId: '86601', srcip: '192.168.2.92' });
    deleteMute('86601', '192.168.2.200');
    const remaining = listMutes();
    expect(remaining.length).toBe(1);
    expect(remaining[0].srcip).toBe('192.168.2.92');
  });
});

describe('listMutes', () => {
  test('hides expired mutes by default and shows them on request', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200', ttlDays: -1 }); // clamps to 0 -> never expires
    createMute({ ruleId: '2027390', srcip: '', ttlDays: 30 });
    // Force one row to be expired by writing a past timestamp directly.
    const { getMutesDb } = require('./mutes');
    getMutesDb()
      .query('UPDATE alert_mutes SET expires_at = ? WHERE rule_id = ?')
      .run(new Date(Date.now() - 1000).toISOString(), '2027390');

    expect(listMutes().map(m => m.ruleId)).toEqual(['86601']);
    expect(listMutes(true).length).toBe(2);
  });
});

describe('isMuted', () => {
  test('matches on Wazuh rule id plus source ip', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200' });
    const mutes = listMutes();
    expect(isMuted(alert({ srcip: '192.168.2.200' }), mutes)).toBe(true);
  });

  test('does NOT mute the same rule from a different source', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200' });
    const mutes = listMutes();
    // This is the whole point of rule+srcip: a server doing Telegram still alerts.
    expect(isMuted(alert({ srcip: '192.168.2.92' }), mutes)).toBe(false);
  });

  test('wildcard srcip mutes the rule from every source', () => {
    createMute({ ruleId: '86601', srcip: SRCIP_ANY });
    const mutes = listMutes();
    expect(isMuted(alert({ srcip: '192.168.2.200' }), mutes)).toBe(true);
    expect(isMuted(alert({ srcip: '8.8.8.8' }), mutes)).toBe(true);
  });

  test('matches a Suricata alert on its signature id', () => {
    createMute({ ruleId: '2027390', srcip: '192.168.2.200' });
    const mutes = listMutes();
    const suricata = alert({
      rule: { level: 3, description: 'Suricata: Alert', id: '86601' },
      srcip: '192.168.2.200',
      data: { alert: { signature_id: 2027390 } },
    } as Partial<WazuhAlert>);
    expect(isMuted(suricata, mutes)).toBe(true);
  });

  test('an expired mute stops hiding alerts', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200', ttlDays: 30 });
    const mutes = listMutes();
    const wayLater = new Date(Date.now() + 31 * 24 * 60 * 60 * 1000);
    expect(isMuted(alert({ srcip: '192.168.2.200' }), mutes)).toBe(true);
    expect(isMuted(alert({ srcip: '192.168.2.200' }), mutes, wayLater)).toBe(false);
  });

  test('no mutes means nothing is hidden', () => {
    expect(isMuted(alert({ srcip: '192.168.2.200' }), [])).toBe(false);
  });

  test('a different rule from the muted source still alerts', () => {
    createMute({ ruleId: '86601', srcip: '192.168.2.200' });
    const mutes = listMutes();
    const other = alert({
      rule: { level: 12, description: 'Password guessing', id: '5712' },
      srcip: '192.168.2.200',
    } as Partial<WazuhAlert>);
    expect(isMuted(other, mutes)).toBe(false);
  });
});

describe('alertSrcip', () => {
  test('prefers the top-level srcip', () => {
    expect(alertSrcip(alert({ srcip: '1.2.3.4' }))).toBe('1.2.3.4');
  });

  test('falls back to Suricata EVE src_ip', () => {
    expect(alertSrcip(alert({ data: { src_ip: '5.6.7.8' } } as Partial<WazuhAlert>))).toBe('5.6.7.8');
  });

  test('returns empty string when there is no source', () => {
    expect(alertSrcip(alert())).toBe('');
  });
});

describe('resolveMutesDbPath', () => {
  test('rejects a NUL byte', () => {
    process.env.MUTES_DB_PATH = 'bad\0path.sqlite';
    expect(() => resolveMutesDbPath()).toThrow('NUL byte');
  });
});
