/**
 * Alert triage provider.
 *
 * Env-switchable backends for alert triage (interactive chat and future batch
 * auto-triage). Callable outside the HTTP request path.
 *
 * TRIAGE_PROVIDER:
 *   claude    (default) - ssh to Mac Studio, run `claude -p` on Claude Max
 *   ollama              - local Ollama (DellAI). Survives slow generations.
 *   anthropic           - paid Anthropic Messages API (legacy path in pai-client)
 *
 * Three traps already paid for (do not rediscover):
 *  1. ANTHROPIC_API_KEY must be UNSET on the remote side or the CLI silently
 *     bills the paid API instead of the subscription.
 *  2. --disallowedTools is VARIADIC and eats every following non-flag argument
 *     including the prompt. Follow it with another flag; send the prompt on stdin.
 *  3. Bun's fetch caps at 300s and IGNORES AbortSignal. Long Ollama calls need
 *     `timeout: false` or they die at exactly 300.0s.
 */

import type { WazuhAlert, PAIChatMessage, PAIChatResponse } from './types';
import { fetchAlertHistory, formatAlertHistory } from './alert-history';

export type TriageProvider = 'claude' | 'ollama' | 'anthropic';

/** Client-facing provider toggle (Cloud / Local). */
export type ClientAIProvider = 'anthropic' | 'ollama' | 'claude';

export interface TriageOptions {
  /** Override resolved provider. Defaults to getTriageProvider(). */
  provider?: TriageProvider;
  ollamaUrl?: string;
  ollamaModel?: string;
  /** Optional prebuilt system prompt. Defaults to buildSystemPrompt(alertContext). */
  systemPrompt?: string;
}

export interface TriageResult extends PAIChatResponse {
  /** Which backend actually produced the text (after any fallback). */
  providerUsed?: TriageProvider | 'ollama';
}

const DEFAULT_OLLAMA_URL = 'http://localhost:11434';
const DEFAULT_OLLAMA_MODEL = 'gemma4:31b';

/**
 * Read TRIAGE_PROVIDER from the environment. Default: claude.
 */
export function getTriageProvider(): TriageProvider {
  const raw = (process.env.TRIAGE_PROVIDER || 'claude').toLowerCase().trim();
  if (raw === 'claude' || raw === 'ollama' || raw === 'anthropic') {
    return raw;
  }
  console.warn(
    `[triage-provider] unknown TRIAGE_PROVIDER="${process.env.TRIAGE_PROVIDER}", using claude`,
  );
  return 'claude';
}

/**
 * Resolve which backend to use for a request.
 *
 * - Client Local toggle (`ollama`) always wins.
 * - Otherwise TRIAGE_PROVIDER env (default claude) selects the cloud/triage backend.
 */
export function resolveTriageProvider(
  clientProvider?: ClientAIProvider,
): TriageProvider {
  if (clientProvider === 'ollama') return 'ollama';
  if (clientProvider === 'claude') return 'claude';
  // clientProvider === 'anthropic' | undefined: honor server env (may still be anthropic)
  return getTriageProvider();
}

function getSeverityLabel(level: number): string {
  if (level >= 12) return 'CRITICAL';
  if (level >= 7) return 'HIGH';
  if (level >= 3) return 'MEDIUM';
  return 'LOW';
}

/**
 * Format alerts as context for the triage model.
 */
export function formatAlertContext(alerts: WazuhAlert[]): string {
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

    if (alert.data?.alert?.signature_id) {
      lines.push(`- **Suricata SID**: ${alert.data.alert.signature_id}`);
    }

    if (alert.full_log) {
      lines.push(
        `- **Log**: \`${alert.full_log.slice(0, 200)}${alert.full_log.length > 200 ? '...' : ''}\``,
      );
    }

    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Build the system prompt (shared across triage backends).
 */
export function buildSystemPrompt(
  alertContext?: WazuhAlert[],
  historyBlock?: string,
): string {
  return `You are a senior security analyst mentoring a junior SOC analyst through Wazuh SIEM alert triage.
Your expertise spans:
- Threat detection and incident response
- MITRE ATT&CK framework
- Network security and log analysis
- Compliance frameworks (PCI DSS, HIPAA, GDPR, NIST)
- Remediation recommendations

## How to Respond

**Always structure your analysis to guide the analyst's thinking, not just give answers:**

1. **What is this?** - Explain the alert in plain language. What triggered it, and what does it mean?
2. **Why does it matter?** - Assess severity and potential impact. Is this urgent or noise?
3. **How do I know?** - Show your reasoning. What fields in the alert led to your conclusion? Teach the analyst what to look at.
4. **What do I do next?** - Give specific, actionable next steps in priority order. Include exact commands, queries, or procedures when applicable.
5. **What should I watch for?** - Related IOCs, follow-up alerts, or escalation triggers that indicate the situation is worsening.

**Tone:** Direct and practical. Explain *why* behind each recommendation so the analyst builds intuition over time. Use markdown formatting - headers, bold, bullet lists, and code blocks - for readability.

If multiple alerts are provided, look for patterns or correlations.

${alertContext ? formatAlertContext(alertContext) : ''}
${historyBlock ?? ''}`;
}

// ---------------------------------------------------------------------------
//
// Why ssh instead of running it here: the CLI is authenticated on the Studio
// via OAuth. Installing it on DellAI would need a fresh interactive /login.
//
// Two load-bearing details:
//  1. ANTHROPIC_API_KEY is unset on the remote side. If it is present, the CLI
//     silently bills the paid API instead of the subscription. That exact
//     silent fallback drained the balance to $0 and killed the briefs on
//     2026-07-25. Unsetting it forces subscription auth and makes failure loud.
//  2. --disallowedTools is VARIADIC and greedily eats every following non-flag
//     argument. It MUST be followed by another flag, never by the prompt. That
//     bug silently broke the PAI daily brief for three days in July 2026.
//     Here the prompt arrives on stdin, and --output-format follows the list.
// ---------------------------------------------------------------------------
export async function sendClaudeCliMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  alertContext?: WazuhAlert[],
  systemPromptOverride?: string,
): Promise<PAIChatResponse> {
  // No default. This repo is public, so the ssh target must never be baked in.
  // Same rule that came out of the 2026-05-05 hardcoded-password leak: require
  // the env var, no fallback.
  const host = process.env.CLAUDE_CLI_SSH_HOST;
  if (!host) {
    throw new Error(
      'CLAUDE_CLI_SSH_HOST is not set. Set it to user@host for the machine holding the Claude CLI session, or set TRIAGE_PROVIDER=ollama.',
    );
  }
  const model = process.env.CLAUDE_CLI_MODEL ?? 'claude-sonnet-5';
  const bin = process.env.CLAUDE_CLI_BIN ?? '/opt/homebrew/bin/claude';
  const timeoutMs = Number(process.env.CLAUDE_CLI_TIMEOUT_MS ?? 900_000);

  // Run the historical lookup HERE, not in the model. See alert-history.ts for
  // why the tool grant was tried and reverted. Failure is non-fatal: triage
  // without history beats no triage, and the block says the lookup failed so the
  // model cannot silently imply it checked.
  const primary = alertContext?.[0];
  const alertHistory = primary?.rule?.id
    ? await fetchAlertHistory(primary.rule.id, primary.agent?.ip)
    : null;
  const historyBlock = formatAlertHistory(alertHistory);
  const systemPrompt =
    systemPromptOverride ?? buildSystemPrompt(alertContext, historyBlock);
  const history = chatHistory
    .map((m) => `${m.role === 'user' ? 'User' : 'Assistant'}: ${m.content}`)
    .join('\n\n');
  const fullPrompt = [systemPrompt, history, userMessage]
    .filter(Boolean)
    .join('\n\n---\n\n');

  const remote = [
    'export PATH=$HOME/.bun/bin:/opt/homebrew/bin:$PATH;',
    'unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN;',
    bin,
    '-p',
    '--model', model,
    '--disallowedTools Bash Edit Write Read WebSearch WebFetch',
    '--output-format text',
    '--no-session-persistence',
  ].join(' ');

  let proc: ReturnType<typeof Bun.spawn> | undefined;
  try {
    proc = Bun.spawn(
      ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, remote],
      { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' },
    );

    // Bun types stdin as number | FileSink when piped; FileSink is what we get.
    const stdin = proc.stdin as unknown as { write(data: string): void; end(): void };
    stdin.write(fullPrompt);
    stdin.end();

    const killer = setTimeout(() => {
      try {
        proc?.kill();
      } catch {
        /* already gone */
      }
    }, timeoutMs);

    const [out, err, code] = await Promise.all([
      new Response(proc.stdout as ReadableStream).text(),
      new Response(proc.stderr as ReadableStream).text(),
      proc.exited,
    ]);
    clearTimeout(killer);

    if (code !== 0) {
      console.error('[triage-provider] claude-cli exit', code, err.slice(0, 400));
      return {
        success: false,
        error: `Claude CLI failed (exit ${code}): ${err.slice(0, 200)}`,
      };
    }

    const content = out.trim();
    if (!content) {
      return { success: false, error: 'Claude CLI returned empty output' };
    }
    return { success: true, content };
  } catch (error: unknown) {
    console.error('[triage-provider] claude-cli error:', error);
    try {
      proc?.kill();
    } catch {
      /* noop */
    }
    const msg = error instanceof Error ? error.message : String(error);
    return { success: false, error: `Claude CLI error: ${msg}` };
  }
}

/**
 * Local Ollama triage. Uses the native /api/chat endpoint and lifts Bun's
 * 300s fetch ceiling so large local models can finish.
 */
export async function sendOllamaMessage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  alertContext: WazuhAlert[] | undefined,
  ollamaUrl: string,
  ollamaModel: string,
  systemPromptOverride?: string,
): Promise<PAIChatResponse> {
  try {
    if (!ollamaModel) {
      return {
        success: false,
        error: 'No Ollama model selected. Open settings to choose a model.',
      };
    }

    const systemPrompt = systemPromptOverride ?? buildSystemPrompt(alertContext);
    const messages = [
      { role: 'system', content: systemPrompt },
      ...chatHistory.map((m) => ({ role: m.role, content: m.content })),
      { role: 'user', content: userMessage },
    ];

    const controller = new AbortController();
    // Local 31B triage can run many minutes; keep a generous outer bound.
    const timeout = setTimeout(() => controller.abort(), 1_800_000);

    const response = await fetch(`${ollamaUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: ollamaModel,
        messages,
        stream: false,
        options: {
          num_ctx: 32768,
          num_predict: 8192,
        },
      }),
      signal: controller.signal,
      // Bun caps fetch at 300s and ignores AbortSignal for that ceiling.
      // A local 31B generation can run well past 5 min, so the cap must be lifted.
      timeout: false,
    } as RequestInit & { timeout: false });

    clearTimeout(timeout);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[triage-provider] Ollama error:', response.status, errorText);
      return {
        success: false,
        error: `Ollama error: ${response.status} - is Ollama running at ${ollamaUrl}?`,
      };
    }

    const data = (await response.json()) as {
      message?: { content?: string };
      prompt_eval_count?: number;
    };

    const NUM_CTX = 32768;
    const promptTokens = data.prompt_eval_count ?? 0;
    if (promptTokens >= NUM_CTX * 0.9) {
      console.error(
        `[triage-provider] WARNING: prompt ${promptTokens} tokens vs num_ctx ${NUM_CTX} - ` +
          'input was likely truncated. Triage may be built on partial data.',
      );
    }

    const content = data.message?.content ?? '';
    if (!content) {
      return { success: false, error: 'Ollama returned empty output' };
    }
    return { success: true, content };
  } catch (error: unknown) {
    console.error('[triage-provider] Ollama error:', error);
    const err = error as { name?: string };
    if (err?.name === 'AbortError') {
      return {
        success: false,
        error: 'Ollama request timed out. Try a smaller model for faster responses.',
      };
    }
    const msg = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: `Ollama connection failed: ${msg}. Is Ollama running?`,
    };
  }
}

/**
 * Run alert triage via the configured provider.
 *
 * Callable from HTTP handlers or batch jobs. Does not talk to the Anthropic
 * HTTP API: when TRIAGE_PROVIDER=anthropic, the caller (pai-client sendChatMessage)
 * keeps the existing tool-use path. This function handles claude and ollama only.
 *
 * On claude-cli failure, falls back to ollama and logs which provider served.
 */
export async function runTriage(
  userMessage: string,
  chatHistory: PAIChatMessage[],
  alertContext?: WazuhAlert[],
  options: TriageOptions = {},
): Promise<TriageResult> {
  const provider = options.provider ?? getTriageProvider();
  const ollamaUrl = options.ollamaUrl || process.env.OLLAMA_URL || DEFAULT_OLLAMA_URL;
  const ollamaModel =
    options.ollamaModel || process.env.OLLAMA_MODEL || DEFAULT_OLLAMA_MODEL;
  const systemPrompt = options.systemPrompt;

  if (provider === 'anthropic') {
    return {
      success: false,
      error:
        'runTriage does not call the Anthropic API. Use sendChatMessage with TRIAGE_PROVIDER=anthropic for the tool-use path.',
    };
  }

  if (provider === 'ollama') {
    const result = await sendOllamaMessage(
      userMessage,
      chatHistory,
      alertContext,
      ollamaUrl,
      ollamaModel,
      systemPrompt,
    );
    if (result.success) {
      console.log('[triage-provider] served by ollama');
    }
    return { ...result, providerUsed: 'ollama' };
  }

  // provider === 'claude'
  const viaCli = await sendClaudeCliMessage(
    userMessage,
    chatHistory,
    alertContext,
    systemPrompt,
  );
  if (viaCli.success) {
    console.log('[triage-provider] served by claude-cli');
    return { ...viaCli, providerUsed: 'claude' };
  }

  // Studio asleep, off the LAN, or ssh refused. Degraded triage beats none.
  console.error(
    '[triage-provider] claude-cli failed, falling back to local ollama:',
    viaCli.error,
  );
  const viaOllama = await sendOllamaMessage(
    userMessage,
    chatHistory,
    alertContext,
    ollamaUrl,
    ollamaModel,
    systemPrompt,
  );
  if (viaOllama.success) {
    console.log('[triage-provider] served by ollama (fallback from claude-cli)');
  } else {
    console.error(
      '[triage-provider] ollama fallback also failed:',
      viaOllama.error,
    );
  }
  return {
    ...viaOllama,
    providerUsed: 'ollama',
    // Preserve the claude error if ollama also failed, for clearer ops signal.
    error: viaOllama.success
      ? undefined
      : `claude-cli failed (${viaCli.error}); ollama fallback failed (${viaOllama.error})`,
  };
}
