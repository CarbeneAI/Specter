/**
 * Specter Dashboard Client Types
 */

export interface WazuhAlert {
  id?: number;
  timestamp: string;
  rule: {
    level: number;
    description: string;
    id: string;
    mitre?: {
      id: string[];
      tactic: string[];
      technique: string[];
    };
    groups?: string[];
    pci_dss?: string[];
    gdpr?: string[];
    hipaa?: string[];
    nist_800_53?: string[];
  };
  agent: {
    id: string;
    name: string;
    ip?: string;
  };
  manager?: {
    name: string;
  };
  full_log?: string;
  data?: Record<string, any>;
  location?: string;
  decoder?: {
    name: string;
  };
  syscheck?: {
    path?: string;
    event?: string;
    mode?: string;
  };
  srcip?: string;
  srcuser?: string;
  dstip?: string;
  dstuser?: string;
  dstport?: string;
  protocol?: string;
  action?: string;
  /** Deterministic pre-triage verdict attached by the server's scorer (apps/server/src/scorer.ts). */
  verdict?: ScoreVerdict;
}

// ---------------------------------------------------------------------------
// Scorer types -- hand-mirrored from apps/server/src/scorer.ts (docs/architecture-scorer-ledger.md
// section 4.1). No shared package between client/server; keep these in sync
// field-for-field when the server types change.
// ---------------------------------------------------------------------------

/** Alert bands, ordered most->least severe, plus 'noise' for alert-fatigue suppression candidates. */
export type ScoreBand = 'critical' | 'high' | 'medium' | 'low' | 'noise';

export interface ScoreVerdict {
  score: number; // 0-100, clamped
  band: ScoreBand;
  reasons: string[]; // human-readable, e.g. "rule level 12 (critical) (+90)"
  signals: Record<string, number>; // named signal -> point contribution, for transparency/teaching
  backend: string; // which backend produced this, e.g. 'local-deterministic'
}

// ---------------------------------------------------------------------------
// Ledger types -- hand-mirrored from apps/server/src/ledger.ts (docs/architecture-scorer-ledger.md
// section 4.2).
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

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

// ---------------------------------------------------------------------------
// Alert mutes -- hand-mirrored from apps/server/src/mutes.ts.
//
// A mute hides an alert in this dashboard only. The alert is still ingested,
// still scored, and still searchable in Wazuh. That is the difference between a
// mute and the upstream "suppress" path, which disables the signature at the
// sensor / manager and destroys the data.
// ---------------------------------------------------------------------------

export interface Mute {
  id: number;
  ruleId: string;
  /** '*' = this rule from any source. '' = alerts carrying no source IP. */
  srcip: string;
  description: string;
  reason: string;
  createdAt: string;
  /** ISO timestamp, or null for a mute that never expires. */
  expiresAt: string | null;
  createdBy: string;
}

/** Wildcard srcip meaning "this rule from any source". */
export const SRCIP_ANY = '*';

/** Default mute lifetime in days. Keep in sync with the server. */
export const DEFAULT_MUTE_TTL_DAYS = 30;

/**
 * One collapsed row in the feed: every alert sharing a rule id + source IP.
 * `latest` is the newest member and drives the row's rendering.
 */
export interface AlertGroup {
  key: string;
  ruleId: string;
  srcip: string;
  description: string;
  count: number;
  latest: WazuhAlert;
  /** Newest first, including `latest`. */
  alerts: WazuhAlert[];
  firstSeen: string;
  lastSeen: string;
  /** Highest rule level in the group -- a group is as severe as its worst member. */
  maxLevel: number;
}

export interface AlertStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface FilterOptions {
  agents: string[];
  ruleGroups: string[];
}

export interface WebSocketMessage {
  type: 'initial' | 'alert' | 'stats' | 'filtered' | 'pong';
  data: WazuhAlert | WazuhAlert[] | AlertStats;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
}

export interface ChatResponse {
  success: boolean;
  content?: string;
  error?: string;
  investigationId?: string; // lets /chat callers build a permalink into the ledger
}

export interface QuickPrompts {
  analyze: string;
  remediation: string;
  related: string;
  ioc: string;
  mitre: string;
}

/** Cloud/Local toggle. Server routes Cloud via TRIAGE_PROVIDER (default claude). */
export type AIProvider = 'anthropic' | 'ollama' | 'claude';

export interface AIProviderConfig {
  provider: AIProvider;
  ollamaUrl: string;
  ollamaModel: string;
  availableModels: string[];
}

/**
 * Get severity level from Wazuh rule level
 */
export function getSeverityLevel(level: number): SeverityLevel {
  if (level >= 12) return 'critical';
  if (level >= 7) return 'high';
  if (level >= 3) return 'medium';
  return 'low';
}

/**
 * Get severity label
 */
export function getSeverityLabel(level: number): string {
  if (level >= 12) return 'Critical';
  if (level >= 7) return 'High';
  if (level >= 3) return 'Medium';
  return 'Low';
}
