/**
 * useMutes - client-side mute matching.
 *
 * Mirrors isMuted() in apps/server/src/mutes.ts so the feed can hide a muted
 * alert the instant you click Mute, without waiting for the next poll. The
 * server remains the source of truth; this is the optimistic half.
 *
 * Keep the matching rules here field-for-field in sync with the server.
 */

import type { WazuhAlert, Mute } from '../types';
import { SRCIP_ANY } from '../types';
import { alertRuleKey, alertSrcip } from './useAlertGroups';

/**
 * True when an active mute hides this alert.
 *
 * Matches when the mute's rule id equals either the Wazuh rule id or the
 * Suricata signature id, AND the source IP matches exactly or the mute uses the
 * '*' wildcard. Expired mutes never match.
 */
export function isMutedClient(alert: WazuhAlert, mutes: Mute[], now: Date = new Date()): boolean {
  if (mutes.length === 0) return false;

  const nowMs = now.getTime();
  const wazuhRuleId = String(alert.rule?.id ?? '');
  const ruleKey = alertRuleKey(alert); // Suricata SID when present, else rule id
  const ip = alertSrcip(alert);

  for (const mute of mutes) {
    if (mute.expiresAt && new Date(mute.expiresAt).getTime() <= nowMs) continue;
    if (mute.ruleId !== wazuhRuleId && mute.ruleId !== ruleKey) continue;
    if (mute.srcip !== SRCIP_ANY && mute.srcip !== ip) continue;
    return true;
  }
  return false;
}
