/**
 * Tests for useAlertGroups + useMutes (client-side).
 *
 * The grouping invariant that matters most: collapsing must never lose an
 * alert and must never hide severity. A group is as severe as its worst
 * member, so one level-12 inside 9,000 ET INFO alerts still sorts as critical
 * instead of disappearing into the noise.
 */

import { describe, test, expect } from 'bun:test';
import { groupAlerts, alertRuleKey, alertSrcip } from './useAlertGroups';
import { isMutedClient } from './useMutes';
import type { WazuhAlert, Mute } from '../types';

let seq = 0;

function mk(
  sid: number | null,
  srcip: string,
  level: number,
  description: string,
  minutesAgo: number,
): WazuhAlert {
  return {
    id: ++seq,
    timestamp: new Date(Date.now() - minutesAgo * 60_000).toISOString(),
    rule: { level, description, id: '86601' },
    agent: { id: '001', name: 'Suricata' },
    srcip,
    ...(sid ? { data: { alert: { signature_id: sid } } } : {}),
  } as WazuhAlert;
}

function mute(overrides: Partial<Mute> = {}): Mute {
  return {
    id: 1,
    ruleId: '2027390',
    srcip: '192.168.2.200',
    description: '',
    reason: '',
    createdAt: new Date().toISOString(),
    expiresAt: null,
    createdBy: 'test',
    ...overrides,
  };
}

describe('alertRuleKey', () => {
  test('uses the Suricata SID when present', () => {
    expect(alertRuleKey(mk(2027390, '1.2.3.4', 3, 'x', 0))).toBe('2027390');
  });

  test('falls back to the Wazuh rule id', () => {
    expect(alertRuleKey(mk(null, '1.2.3.4', 3, 'x', 0))).toBe('86601');
  });
});

describe('alertSrcip', () => {
  test('reads the top-level srcip', () => {
    expect(alertSrcip(mk(null, '192.168.2.200', 3, 'x', 0))).toBe('192.168.2.200');
  });

  test('returns empty string when absent', () => {
    expect(alertSrcip(mk(null, '', 3, 'x', 0))).toBe('');
  });
});

describe('groupAlerts', () => {
  test('collapses a realistic noisy feed without losing alerts', () => {
    const alerts = [
      ...Array.from({ length: 40 }, (_, i) => mk(2027390, '192.168.2.200', 3, 'ET INFO Telegram SNI', i)),
      ...Array.from({ length: 12 }, (_, i) => mk(2027390, '192.168.2.92', 3, 'ET INFO Telegram SNI', i)),
      ...Array.from({ length: 8 }, (_, i) => mk(2019416, '192.168.2.1', 3, 'ET DOS SSDP', i)),
      mk(null, '10.0.0.5', 12, 'Password guessing', 2),
    ];
    const groups = groupAlerts(alerts);

    expect(groups.length).toBe(4);
    // Nothing may be dropped by collapsing.
    expect(groups.reduce((n, g) => n + g.count, 0)).toBe(alerts.length);
  });

  test('keeps the same rule from different sources as separate groups', () => {
    const groups = groupAlerts([
      mk(2027390, '192.168.2.200', 3, 'Telegram', 1),
      mk(2027390, '192.168.2.92', 3, 'Telegram', 2),
    ]);
    expect(groups.length).toBe(2);
  });

  test('a group is as severe as its worst member', () => {
    // The failure mode this guards: one real alert buried in thousands of ET INFO.
    const groups = groupAlerts([
      ...Array.from({ length: 50 }, (_, i) => mk(2027390, '192.168.2.200', 3, 'noise', i + 1)),
      mk(2027390, '192.168.2.200', 12, 'noise', 0),
    ]);
    expect(groups.length).toBe(1);
    expect(groups[0].maxLevel).toBe(12);
  });

  test('orders groups newest first', () => {
    const groups = groupAlerts([
      mk(1111, 'a', 3, 'old', 100),
      mk(2222, 'b', 3, 'new', 1),
    ]);
    expect(groups[0].ruleId).toBe('2222');
  });

  test('orders members newest first within a group', () => {
    const groups = groupAlerts([
      mk(2027390, 'a', 3, 'x', 50),
      mk(2027390, 'a', 3, 'x', 1),
      mk(2027390, 'a', 3, 'x', 20),
    ]);
    const times = groups[0].alerts.map(a => new Date(a.timestamp).getTime());
    expect(times).toEqual([...times].sort((x, y) => y - x));
    expect(groups[0].latest).toBe(groups[0].alerts[0]);
  });

  test('tracks the first/last seen span', () => {
    const groups = groupAlerts([
      mk(2027390, 'a', 3, 'x', 60),
      mk(2027390, 'a', 3, 'x', 0),
    ]);
    expect(new Date(groups[0].firstSeen).getTime())
      .toBeLessThan(new Date(groups[0].lastSeen).getTime());
  });

  test('handles an empty feed', () => {
    expect(groupAlerts([])).toEqual([]);
  });
});

describe('isMutedClient', () => {
  test('matches rule + source', () => {
    expect(isMutedClient(mk(2027390, '192.168.2.200', 3, 'x', 0), [mute()])).toBe(true);
  });

  test('does not mute the same rule from another source', () => {
    expect(isMutedClient(mk(2027390, '192.168.2.92', 3, 'x', 0), [mute()])).toBe(false);
  });

  test('wildcard matches every source', () => {
    expect(isMutedClient(mk(2027390, '8.8.8.8', 3, 'x', 0), [mute({ srcip: '*' })])).toBe(true);
  });

  test('expired mutes stop matching', () => {
    const expired = mute({ expiresAt: new Date(Date.now() - 1000).toISOString() });
    expect(isMutedClient(mk(2027390, '192.168.2.200', 3, 'x', 0), [expired])).toBe(false);
  });

  test('no mutes means nothing hidden', () => {
    expect(isMutedClient(mk(2027390, '192.168.2.200', 3, 'x', 0), [])).toBe(false);
  });

  test('client matching agrees with the grouping key', () => {
    // A mute created from a group row must hide exactly that group.
    const alert = mk(2027390, '192.168.2.200', 3, 'x', 0);
    const group = groupAlerts([alert])[0];
    const m = mute({ ruleId: group.ruleId, srcip: group.srcip });
    expect(isMutedClient(alert, [m])).toBe(true);
  });
});
