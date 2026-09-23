/**
 * useAlertGroups - collapse a flat alert list into rule+srcip groups.
 *
 * Specter's feed is dominated by a handful of repeating signatures (ET INFO
 * Telegram SNI alone was 9,292 of 15,101 alerts in one 24h window). Rendering
 * those as individual rows makes triage impossible: the two alerts that matter
 * are buried under thousands that don't.
 *
 * Grouping key is `ruleId::srcip` -- the same key a mute uses, so "collapse
 * this" and "mute this" line up exactly. A group is as severe as its worst
 * member (maxLevel), so a noisy group that suddenly contains one level-12 alert
 * sorts up instead of hiding it.
 *
 * Pure function of its input: no fetches, no side effects, safe to call inside a
 * computed().
 */

import type { WazuhAlert, AlertGroup } from '../types';

/** The mute/group identity of an alert: Suricata SID when present, else Wazuh rule id. */
export function alertRuleKey(alert: WazuhAlert): string {
  const sid = (alert.data as Record<string, any> | undefined)?.alert?.signature_id;
  if (sid !== undefined && sid !== null && String(sid) !== '') return String(sid);
  return String(alert.rule?.id ?? '');
}

/** Source IP of an alert, checking the top-level field then Suricata's EVE fields. */
export function alertSrcip(alert: WazuhAlert): string {
  const data = alert.data as Record<string, any> | undefined;
  return String(alert.srcip || data?.src_ip || data?.srcip || '');
}

function timeOf(alert: WazuhAlert): number {
  const t = new Date(alert.timestamp).getTime();
  return Number.isNaN(t) ? 0 : t;
}

/**
 * Group alerts by rule + source IP, newest group first.
 *
 * Within a group, members are newest-first. Groups are ordered by their most
 * recent alert so the feed still reads as a live feed -- a group resurfaces to
 * the top when it fires again.
 */
export function groupAlerts(alerts: WazuhAlert[]): AlertGroup[] {
  const byKey = new Map<string, AlertGroup>();

  for (const alert of alerts) {
    const ruleId = alertRuleKey(alert);
    const srcip = alertSrcip(alert);
    const key = `${ruleId}::${srcip}`;
    const ts = alert.timestamp;

    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, {
        key,
        ruleId,
        srcip,
        description: alert.rule?.description ?? '',
        count: 1,
        latest: alert,
        alerts: [alert],
        firstSeen: ts,
        lastSeen: ts,
        maxLevel: alert.rule?.level ?? 0,
      });
      continue;
    }

    existing.count++;
    existing.alerts.push(alert);
    existing.maxLevel = Math.max(existing.maxLevel, alert.rule?.level ?? 0);
    if (timeOf(alert) > timeOf(existing.latest)) {
      existing.latest = alert;
      existing.lastSeen = ts;
    }
    if (timeOf(alert) < new Date(existing.firstSeen).getTime()) {
      existing.firstSeen = ts;
    }
  }

  const groups = Array.from(byKey.values());
  for (const group of groups) {
    group.alerts.sort((a, b) => timeOf(b) - timeOf(a));
    group.latest = group.alerts[0];
  }
  groups.sort((a, b) => timeOf(b.latest) - timeOf(a.latest));
  return groups;
}
