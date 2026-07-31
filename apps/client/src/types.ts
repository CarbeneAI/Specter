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

export type AIProvider = 'anthropic' | 'ollama';

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
