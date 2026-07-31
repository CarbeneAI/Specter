/**
 * PAI API Client
 * Sends chat messages to PAI for security alert analysis
 * Includes Wazuh Indexer search tool for Claude to query historical alerts
 */

import { homedir } from 'os';
import type { WazuhAlert, PAIChatMessage, PAIChatResponse } from './types';
import {
  createInvestigation,
  appendStep,
  finalizeInvestigation,
  type StepType,
  type LlmStepPayload,
  type ToolCallStepPayload,
  type ToolResultStepPayload,
  type FinalizeInvestigationParams,
} from './ledger';

export type AIProvider = 'anthropic' | 'ollama';

// PAI API configuration
const PAI_API_URL = process.env.PAI_API_URL || 'http://localhost:3001/v1/messages';

// Wazuh Dashboard API configuration (same as alert-ingest.ts)
const WAZUH_DASHBOARD_URL = process.env.WAZUH_DASHBOARD_URL || 'https://wazuh.example.local';
const WAZUH_DASHBOARD_USER = process.env.WAZUH_DASHBOARD_USER || 'admin';
const WAZUH_DASHBOARD_PASSWORD = process.env.WAZUH_DASHBOARD_PASSWORD;
if (!WAZUH_DASHBOARD_PASSWORD) {
  throw new Error('WAZUH_DASHBOARD_PASSWORD env var is required. Refusing to use a hardcoded fallback.');
}

// Tool definition for Anthropic API
const SEARCH_TOOL = {
  name: 'search_wazuh_alerts',
  description: 'Search Wazuh Indexer for security alerts by IP, rule, severity, time range, or keyword. Use this to find historical alerts, correlate events across time, or investigate specific IPs/rules.',
  input_schema: {
    type: 'object' as const,
    properties: {
      query: { type: 'string', description: 'Free text search across rule descriptions and logs' },
      src_ip: { type: 'string', description: 'Source IP address to filter by' },
      dest_ip: { type: 'string', description: 'Destination IP address to filter by' },
      rule_id: { type: 'string', description: 'Wazuh rule ID or Suricata SID' },
      severity_min: { type: 'number', description: 'Minimum rule level (0-15)' },
      time_range: { type: 'string', description: 'Time range: 1h, 6h, 12h, 24h, 3d, 7d, 30d' },
      limit: { type: 'number', description: 'Max results (default 20, max 100)' },
    },
  },
};

const MAX_TOOL_CALLS = 3;

/**
 * Load the Anthropic API key.
 *
 * Resolution order:
 *  1. `WAZUH_PAI_API_KEY` or `ANTHROPIC_API_KEY` from the environment. Bun auto-loads
 *     the repo's `.env` into `process.env`, so the Quick Start flow (put
 *     `ANTHROPIC_API_KEY=sk-ant-...` in `.env`) is satisfied here.
 *  2. A key file, for setups that keep credentials outside the repo. Path comes from
 *     `SPECTER_ENV_FILE`, defaulting to `~/.claude/.env`. Set it explicitly to point
 *     somewhere else, or to a nonexistent path to disable the fallback entirely.
 *
 * Throws if no key is found anywhere, which is what makes the no-key degradation path
 * (deterministic scoring still works, AI chat cleanly reports failure) reachable.
 */
async function getApiKey(): Promise<string> {
  if (process.env.WAZUH_PAI_API_KEY) {
    return process.env.WAZUH_PAI_API_KEY;
  }
  if (process.env.ANTHROPIC_API_KEY) {
    return process.env.ANTHROPIC_API_KEY;
  }

  const envPath = process.env.SPECTER_ENV_FILE || `${homedir()}/.claude/.env`;

  try {
    const envFile = await Bun.file(envPath).text();
    const match = envFile.match(/(?:ANTHROPIC_API_KEY|WAZUH_PAI_API_KEY)=(.+)/);
    if (match) {
      return match[1].trim();
    }
  } catch {
    // Absent/unreadable key file is an expected condition, not an error worth logging.
  }

  throw new Error('No API key found - set WAZUH_PAI_API_KEY or ANTHROPIC_API_KEY');
}

/**
 * Format alerts as context for PAI
 */
function formatAlertContext(alerts: WazuhAlert[]): string {
  if (!alerts || alerts.length === 0) {
    return '';
  }

  const lines = ['## Selected Security Alerts\n'];

  for (const alert of alerts) {
    lines.push(`### Alert: ${alert.rule.description}`);
    lines.push(`- **Severity**: Level ${alert.rule.level} (${getSeverityLabel(alert.rule.level)})`);
    lines.push(`- **Rule ID**: ${alert.rule.id}`);
    lines.push(`- **Agent**: ${alert.agent?.name || 'Unknown'} (${alert.agent?.ip || 'N/A'})`);
    lines.push(`- **Timestamp**: ${alert.timestamp}`);

    if (alert.rule.mitre) {
      lines.push(`- **MITRE ATT&CK**: ${alert.rule.mitre.id?.join(', ') || 'N/A'}`);
      if (alert.rule.mitre.tactic?.length) {
        lines.push(`  - Tactics: ${alert.rule.mitre.tactic.join(', ')}`);
      }
      if (alert.rule.mitre.technique?.length) {
        lines.push(`  - Techniques: ${alert.rule.mitre.technique.join(', ')}`);
      }
    }

    if (alert.srcip) lines.push(`- **Source IP**: ${alert.srcip}`);
    if (alert.srcuser) lines.push(`- **Source User**: ${alert.srcuser}`);
    if (alert.dstip) lines.push(`- **Destination IP**: ${alert.dstip}`);
    if (alert.dstport) lines.push(`- **Destination Port**: ${alert.dstport}`);

    // Include Suricata signature ID if present
    if (alert.data?.alert?.signature_id) {
      lines.push(`- **Suricata SID**: ${alert.data.alert.signature_id}`);
    }

    if (alert.full_log) {
      lines.push(`- **Log**: \`${alert.full_log.slice(0, 200)}${alert.full_log.length > 200 ? '...' : ''}\``);
    }

    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Get severity label from level
 */
function getSeverityLabel(level: number): string {
  if (level >= 12) return 'CRITICAL';
  if (level >= 7) return 'HIGH';
  if (level >= 3) return 'MEDIUM';
  return 'LOW';
}

/**
 * Parse time range string to milliseconds offset from now
 */
function parseTimeRange(timeRange: string): number {
  const match = timeRange.match(/^(\d+)(h|d)$/);
  if (!match) return 24 * 60 * 60 * 1000; // default 24h

  const value = parseInt(match[1]);
  const unit = match[2];

  if (unit === 'h') return value * 60 * 60 * 1000;
  if (unit === 'd') return value * 24 * 60 * 60 * 1000;
  return 24 * 60 * 60 * 1000;
}

/**
 * Search Wazuh Indexer for alerts matching the given parameters
 */
export async function searchWazuhAlerts(params: {
  query?: string;
  src_ip?: string;
  dest_ip?: string;
  rule_id?: string;
  severity_min?: number;
  time_range?: string;
  limit?: number;
}): Promise<{ results: any[]; total: number; error?: string }> {
  try {
    const limit = Math.min(params.limit || 20, 100);

    // Build OpenSearch query DSL
    const must: any[] = [];
    const filter: any[] = [];

    // Free text search across descriptions and logs
    if (params.query) {
      must.push({
        multi_match: {
          query: params.query,
          fields: ['rule.description', 'full_log', 'data.alert.signature'],
          type: 'best_fields',
          fuzziness: 'AUTO',
        },
      });
    }

    // IP filters
    if (params.src_ip) {
      filter.push({
        bool: {
          should: [
            { term: { 'data.src_ip': params.src_ip } },
            { term: { srcip: params.src_ip } },
          ],
        },
      });
    }

    if (params.dest_ip) {
      filter.push({
        bool: {
          should: [
            { term: { 'data.dest_ip': params.dest_ip } },
            { term: { dstip: params.dest_ip } },
          ],
        },
      });
    }

    // Rule ID filter
    if (params.rule_id) {
      filter.push({
        bool: {
          should: [
            { term: { 'rule.id': params.rule_id } },
            { term: { 'data.alert.signature_id': params.rule_id } },
          ],
        },
      });
    }

    // Severity filter
    if (params.severity_min !== undefined) {
      filter.push({
        range: { 'rule.level': { gte: params.severity_min } },
      });
    }

    // Time range filter
    const timeRangeMs = parseTimeRange(params.time_range || '24h');
    const fromTime = new Date(Date.now() - timeRangeMs).toISOString();
    filter.push({
      range: { timestamp: { gte: fromTime } },
    });

    const query: any = {
      size: limit,
      sort: [{ timestamp: { order: 'desc' } }],
      query: {
        bool: {
          must: must.length > 0 ? must : [{ match_all: {} }],
          filter,
        },
      },
    };

    // Use Dashboard API proxy (same pattern as alert-ingest.ts)
    const searchPath = encodeURIComponent('wazuh-alerts-*/_search');
    const response = await fetch(
      `${WAZUH_DASHBOARD_URL}/api/console/proxy?path=${searchPath}&method=POST`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${btoa(`${WAZUH_DASHBOARD_USER}:${WAZUH_DASHBOARD_PASSWORD}`)}`,
          'osd-xsrf': 'true',
        },
        body: JSON.stringify(query),
        // @ts-ignore - Bun supports this for self-signed certs
        tls: { rejectUnauthorized: false },
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Wazuh search failed: ${response.status}`, errorText);
      return { results: [], total: 0, error: `Indexer query failed: ${response.status}` };
    }

    const data = await response.json() as any;
    const hits = data.hits?.hits || [];
    const total = data.hits?.total?.value || hits.length;

    const results = hits.map((hit: any) => {
      const src = hit._source;
      return {
        timestamp: src.timestamp,
        rule_id: src.rule?.id,
        rule_level: src.rule?.level,
        rule_description: src.rule?.description,
        agent_name: src.agent?.name,
        src_ip: src.data?.src_ip || src.srcip,
        dest_ip: src.data?.dest_ip || src.dstip,
        dest_port: src.data?.dest_port || src.dstport,
        protocol: src.data?.proto || src.protocol,
        suricata_sid: src.data?.alert?.signature_id,
        suricata_signature: src.data?.alert?.signature,
        mitre_ids: src.rule?.mitre?.id,
        full_log: src.full_log?.slice(0, 300),
      };
    });

    return { results, total };
  } catch (error) {
    console.error('Wazuh search error:', error);
    return {
      results: [],
      total: 0,
      error: error instanceof Error ? error.message : 'Search failed',
    };
  }
}

/**
 * Format search results as text for Claude tool_result
 */
function formatSearchResults(searchResult: { results: any[]; total: number; error?: string }): string {
  if (searchResult.error) {
    return `Search error: ${searchResult.error}`;
  }

  if (searchResult.results.length === 0) {
    return 'No alerts found matching the search criteria.';
  }

  const lines = [`Found ${searchResult.total} total alerts (showing ${searchResult.results.length}):\n`];

  for (const r of searchResult.results) {
    lines.push(`- [${r.timestamp}] Level ${r.rule_level} | Rule ${r.rule_id}${r.suricata_sid ? ` (SID ${r.suricata_sid})` : ''}`);
    lines.push(`  ${r.rule_description}`);
    if (r.src_ip) lines.push(`  Src: ${r.src_ip} → Dst: ${r.dest_ip || 'N/A'}:${r.dest_port || 'N/A'}`);
    if (r.agent_name) lines.push(`  Agent: ${r.agent_name}`);
    if (r.mitre_ids?.length) lines.push(`  MITRE: ${r.mitre_ids.join(', ')}`);
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Send a chat message via Ollama's OpenAI-compatible API
 */
async function sendOllamaMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  alertContext: WazuhAlert[] | undefined,
  ollamaUrl: string,
  ollamaModel: string,
): Promise<PAIChatResponse> {
  try {
    const systemPrompt = buildSystemPrompt(alertContext);

    const messages = [
      { role: 'system', content: systemPrompt },
      ...chatHistory.map(m => ({ role: m.role, content: m.content })),
      { role: 'user', content: userMessage },
    ];

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000); // 2 min timeout

    const response = await fetch(`${ollamaUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: ollamaModel,
        messages,
        max_tokens: 2048,
        stream: false,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Ollama API error:', response.status, errorText);
      return { success: false, error: `Ollama error: ${response.status} - is Ollama running at ${ollamaUrl}?` };
    }

    const data = await response.json() as any;
    const content = data.choices?.[0]?.message?.content || '';

    return { success: true, content };
  } catch (error: any) {
    console.error('Ollama error:', error);
    if (error?.name === 'AbortError') {
      return { success: false, error: 'Ollama request timed out (2 min). Try a smaller model for faster responses.' };
    }
    const msg = error instanceof Error ? error.message : 'Unknown error';
    return { success: false, error: `Ollama connection failed: ${msg}. Is Ollama running?` };
  }
}

/**
 * Fetch available models from Ollama
 */
export async function getOllamaModels(ollamaUrl: string): Promise<string[]> {
  try {
    const response = await fetch(`${ollamaUrl}/api/tags`);
    if (!response.ok) return [];
    const data = await response.json() as any;
    return (data.models || []).map((m: any) => m.name);
  } catch {
    return [];
  }
}

/**
 * Build the system prompt (shared between providers)
 */
function buildSystemPrompt(alertContext?: WazuhAlert[]): string {
  return `You are a senior security analyst mentoring a junior SOC analyst through Wazuh SIEM alert triage.
Your expertise spans:
- Threat detection and incident response
- MITRE ATT&CK framework
- Network security and log analysis
- Compliance frameworks (PCI DSS, HIPAA, GDPR, NIST)
- Remediation recommendations

## How to Respond

**Always structure your analysis to guide the analyst's thinking, not just give answers:**

1. **What is this?** — Explain the alert in plain language. What triggered it, and what does it mean?
2. **Why does it matter?** — Assess severity and potential impact. Is this urgent or noise?
3. **How do I know?** — Show your reasoning. What fields in the alert led to your conclusion? Teach the analyst what to look at.
4. **What do I do next?** — Give specific, actionable next steps in priority order. Include exact commands, queries, or procedures when applicable.
5. **What should I watch for?** — Related IOCs, follow-up alerts, or escalation triggers that indicate the situation is worsening.

**Tone:** Direct and practical. Explain *why* behind each recommendation so the analyst builds intuition over time. Use markdown formatting — headers, bold, bullet lists, and code blocks — for readability.

If multiple alerts are provided, look for patterns or correlations.

${alertContext ? formatAlertContext(alertContext) : ''}`;
}

/**
 * Guarded ledger.ts wrapper: no-op if investigationId is undefined (i.e.
 * createInvestigation already failed), and never rethrows -- a bun:sqlite
 * write failure must never break the chat response (fail-open, per
 * docs/architecture-scorer-ledger.md section 6 / 1 Goals).
 */
function safeAppendStep(
  investigationId: string | undefined,
  seq: number,
  type: StepType,
  payload: LlmStepPayload | ToolCallStepPayload | ToolResultStepPayload
): void {
  if (!investigationId) return;
  try {
    appendStep(investigationId, seq, type, payload);
  } catch (e) {
    console.error('[Ledger] appendStep failed (continuing without ledger):', e);
  }
}

/**
 * Guarded ledger.ts wrapper: no-op if investigationId is undefined, and
 * never rethrows -- same fail-open contract as safeAppendStep.
 */
function safeFinalize(
  investigationId: string | undefined,
  params: FinalizeInvestigationParams
): void {
  if (!investigationId) return;
  try {
    finalizeInvestigation(investigationId, params);
  } catch (e) {
    console.error('[Ledger] finalizeInvestigation failed (continuing without ledger):', e);
  }
}

/**
 * Send a chat message to PAI with optional alert context
 * Supports tool use loop for Wazuh Indexer search (Anthropic only)
 *
 * LEDGER SCOPE: only the Anthropic path is recorded. The Ollama path returns
 * before any ledger call, because it has no tool-use loop to replay -- there is
 * no multi-step investigation to reconstruct. Instrument it here if that changes.
 */
export async function sendChatMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  alertContext?: WazuhAlert[],
  sessionId: string = 'wazuh-dashboard',
  provider: AIProvider = 'anthropic',
  ollamaUrl?: string,
  ollamaModel?: string,
): Promise<PAIChatResponse> {
  // Route to Ollama if selected
  if (provider === 'ollama') {
    if (!ollamaModel) {
      return { success: false, error: 'No Ollama model selected. Open settings to choose a model.' };
    }
    return sendOllamaMessage(
      userMessage,
      chatHistory,
      alertContext,
      ollamaUrl || 'http://localhost:11434',
      ollamaModel,
    );
  }
  const startTime = Date.now();
  let investigationId: string | undefined;
  let seq = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  const CHAT_MODEL = 'claude-sonnet-4-20250514';

  try {
    const apiKey = await getApiKey();

    // Build system prompt with security context + Anthropic-specific tool instructions
    const systemPrompt = buildSystemPrompt(alertContext) + `

## Tools Available

You have a search tool to query the Wazuh Indexer for historical alerts. Use it proactively to:
- Find related alerts from the same source IP
- Check alert frequency and patterns over time
- Correlate events across different time periods
- Determine if an IP or rule has been seen before

When you search, briefly explain *why* you're searching so the analyst learns when to correlate.`;

    // Build messages array - must handle tool_use history correctly
    const messages: any[] = [
      ...chatHistory.map(m => ({
        role: m.role,
        content: m.content,
      })),
      { role: 'user', content: userMessage },
    ];

    // Ledger: open the investigation before the first API call. Verdicts ride
    // along on alertContext[i].verdict -- already attached by alert-ingest.ts's
    // scoreAndAttach(). No new scoring call happens here.
    try {
      investigationId = createInvestigation({
        sessionId,
        alertContext: alertContext ?? null,
        scorerVerdicts: alertContext?.map(a => a.verdict ?? null) ?? null,
        model: CHAT_MODEL,
        systemPrompt,
        userMessage,
      });
    } catch (e) {
      console.error('[Ledger] createInvestigation failed (continuing without ledger):', e);
    }

    // Tool use loop - max MAX_TOOL_CALLS iterations
    let toolCallCount = 0;

    while (toolCallCount <= MAX_TOOL_CALLS) {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: CHAT_MODEL,
          max_tokens: 2048,
          system: systemPrompt,
          tools: [SEARCH_TOOL],
          messages,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        console.error('PAI API error:', response.status, error);
        safeFinalize(investigationId, {
          status: 'error',
          finalAnalysis: null,
          inputTokens: totalInputTokens,
          outputTokens: totalOutputTokens,
          durationMs: Date.now() - startTime,
        });
        return {
          success: false,
          error: `API error: ${response.status}`,
        };
      }

      const data = await response.json() as any;
      totalInputTokens += data.usage?.input_tokens ?? 0;
      totalOutputTokens += data.usage?.output_tokens ?? 0;

      // Ledger: record this raw LLM turn (assistant content blocks, stop reason, usage).
      safeAppendStep(investigationId, seq++, 'llm', {
        role: 'assistant',
        content: data.content,
        stopReason: data.stop_reason,
        usage: data.usage,
      });

      // Check if Claude wants to use a tool
      if (data.stop_reason === 'tool_use') {
        toolCallCount++;

        // Extract tool use blocks
        const toolUseBlocks = (data.content as any[]).filter((block: any) => block.type === 'tool_use');
        const toolResults: any[] = [];

        for (const toolUse of toolUseBlocks) {
          if (toolUse.name === 'search_wazuh_alerts') {
            console.log(`[PAI Chat] Tool call #${toolCallCount}: search_wazuh_alerts`, toolUse.input);

            // Ledger: record the call before executing it.
            safeAppendStep(investigationId, seq++, 'tool_call', {
              toolUseId: toolUse.id,
              name: toolUse.name,
              input: toolUse.input,
            });

            const searchResult = await searchWazuhAlerts(toolUse.input);
            const resultText = formatSearchResults(searchResult);

            // Ledger: record the result actually sent back to Claude.
            safeAppendStep(investigationId, seq++, 'tool_result', {
              toolUseId: toolUse.id,
              resultText,
            });

            toolResults.push({
              type: 'tool_result',
              tool_use_id: toolUse.id,
              content: resultText,
            });
          }
        }

        // Add assistant response and tool results to messages
        messages.push({ role: 'assistant', content: data.content });
        messages.push({ role: 'user', content: toolResults });

        // Continue the loop to get Claude's final response
        continue;
      }

      // No tool use - extract final text response
      const textBlocks = (data.content as any[]).filter((block: any) => block.type === 'text');
      const content = textBlocks.map((block: any) => block.text).join('\n');

      safeFinalize(investigationId, {
        status: 'completed',
        finalAnalysis: content,
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        durationMs: Date.now() - startTime,
      });

      return {
        success: true,
        content,
        investigationId,
      };
    }

    // Hit max tool calls - return what we have
    const maxCallsContent = 'I performed multiple searches but reached the analysis limit. Please refine your question for more targeted results.';
    safeFinalize(investigationId, {
      status: 'completed',
      finalAnalysis: maxCallsContent,
      inputTokens: totalInputTokens,
      outputTokens: totalOutputTokens,
      durationMs: Date.now() - startTime,
    });
    return {
      success: true,
      content: maxCallsContent,
      investigationId,
    };
  } catch (error) {
    console.error('Error calling PAI:', error);
    safeFinalize(investigationId, {
      status: 'error',
      finalAnalysis: null,
      inputTokens: totalInputTokens,
      outputTokens: totalOutputTokens,
      durationMs: Date.now() - startTime,
    });
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Quick analysis prompts
 */
export const QUICK_PROMPTS = {
  analyze: 'Analyze this security alert. Search the Wazuh Indexer for historical alerts from the same source IP and rule ID over the last 7 days to understand frequency and patterns. Then explain what the alert means, how serious it is, and whether the historical context changes your assessment.',
  remediation: 'What are the recommended remediation steps for this alert?',
  related: 'What other types of attacks or alerts might be related to this? What should I look for?',
  ioc: 'What are the key indicators of compromise (IOCs) from this alert that I should add to my blocklist or monitoring?',
  mitre: 'Map this alert to the MITRE ATT&CK framework. What tactics and techniques are involved? Then provide MITRE D3FEND countermeasures — what defensive techniques (Detect, Isolate, Deceive, Evict) should be applied to counter each identified ATT&CK technique? Finally, list Detection Opportunities — what data sources, log types, and detection rules would catch this attack pattern, and provide pseudo-detection logic or Sigma-style rules where applicable.',
};
