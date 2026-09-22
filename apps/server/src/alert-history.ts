/**
 * Historical correlation for triage, fetched by Specter — not by the model.
 *
 * Why this exists
 * ---------------
 * Triage kept answering "I hit a limitation before I could pull historical
 * data: this session doesn't have a local shell/Bash tool available". That was
 * accurate: `sendClaudeCliMessage` passes
 * `--disallowedTools Bash Edit Write Read WebSearch WebFetch`, so the model has
 * no shell by design. The WazuhDashboard skill records the same stall blocking a
 * live triage on 2026-08-21.
 *
 * Why not just grant the tool
 * ---------------------------
 * Tried on 2026-09-22 and reverted. `--allowedTools` is variadic in the same way
 * `--disallowedTools` is (see the comment above sendClaudeCliMessage), so
 * `--allowedTools 'Bash(bun …QueryIndexer.ts:*)' Read` did NOT scope anything —
 * a denial test had the model run `whoami && ls ~/.ssh` and list private key
 * filenames on the Studio. Wazuh alert text is attacker-influenced (hostnames,
 * paths, command lines lifted from real traffic) and that session runs on
 * Clint's daily driver, so a shell there is not an acceptable default.
 *
 * Running the lookup here is strictly better anyway:
 *   - deterministic: history is always present, never dependent on the model
 *     deciding to ask for it (this matters for unattended scheduled response)
 *   - zero added attack surface: no model-controlled command execution
 *   - cheaper: one fixed query instead of an agent loop
 *
 * The tool itself is read-only — `_search`/`_count` only, index and HTTP method
 * fixed in QueryIndexer.ts.
 */
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';

/**
 * Absolute path to QueryIndexer.ts on the CLAUDE_CLI_SSH_HOST machine.
 *
 * No default. This repo is public, so a local filesystem layout must never be
 * baked in -- same rule as CLAUDE_CLI_SSH_HOST in triage-provider.ts, from the
 * 2026-05-05 hardcoded-password leak. Unset simply disables the lookup and
 * triage degrades to no-history rather than failing.
 */
const QUERY_INDEXER = process.env.QUERY_INDEXER_PATH;

/** Env file holding WAZUH_DASHBOARD_PASSWORD; without it the tool exits 2. */
const REMOTE_ENV_FILE = process.env.QUERY_INDEXER_ENV;

const LOOKUP_TIMEOUT_MS = Number(process.env.QUERY_INDEXER_TIMEOUT_MS ?? 60_000);

export interface AlertHistory {
  ruleId: string;
  /** Raw human-readable tool output, already formatted for a prompt. */
  text: string;
  ok: boolean;
}

/**
 * Run QueryIndexer.ts on the Studio over ssh and return its output.
 *
 * Exit codes from the tool: 0 = ran, no matches; 10 = matches found;
 * 1 = query failed; 2 = bad usage or missing password. 0 and 10 are both
 * success for our purposes.
 */
export async function fetchAlertHistory(
  ruleId: string,
  agentIp?: string,
  days = 7,
  sample = 3,
): Promise<AlertHistory | null> {
  const host = process.env.CLAUDE_CLI_SSH_HOST;
  if (!host || !ruleId || !QUERY_INDEXER || !REMOTE_ENV_FILE) return null;

  // Rule IDs and IPs are interpolated into a remote shell command, so refuse
  // anything that is not plainly numeric / dotted-quad. Alert fields are
  // attacker-influenced; this is the injection boundary.
  if (!/^\d{1,10}$/.test(ruleId)) return null;
  const ipArg =
    agentIp && /^\d{1,3}(\.\d{1,3}){3}$/.test(agentIp) ? ` --agent-ip ${agentIp}` : '';

  const remote =
    `export PATH=$HOME/.bun/bin:/opt/homebrew/bin:$PATH; ` +
    `set -a; . ${REMOTE_ENV_FILE} 2>/dev/null; set +a; ` +
    `bun ${QUERY_INDEXER} --rule-id ${ruleId}${ipArg} --days ${days} --sample ${sample} 2>&1`;

  return new Promise<AlertHistory | null>((resolve) => {
    const proc = spawn('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, remote]);
    let out = '';
    const killer = setTimeout(() => {
      try {
        proc.kill();
      } catch {
        /* already gone */
      }
    }, LOOKUP_TIMEOUT_MS);

    proc.stdout.on('data', (d) => (out += d.toString()));
    proc.stderr.on('data', (d) => (out += d.toString()));

    proc.on('error', () => {
      clearTimeout(killer);
      resolve(null);
    });

    proc.on('close', (code) => {
      clearTimeout(killer);
      const ok = code === 0 || code === 10;
      if (!ok || !out.trim()) {
        // Degrade quietly: triage without history beats no triage. The prompt
        // says so explicitly so the model does not claim history was checked.
        resolve({ ruleId, ok: false, text: `(historical lookup unavailable: exit ${code})` });
        return;
      }
      resolve({ ruleId, ok: true, text: out.trim() });
    });
  });
}

/** Render history for injection into the system prompt. */
export function formatAlertHistory(h: AlertHistory | null): string {
  if (!h) return '';
  if (!h.ok) {
    return `\n## Historical correlation\n\n${h.text}\nDo NOT claim this alert is new or recurring — say the lookup was unavailable.\n`;
  }
  return `\n## Historical correlation (already run for you — do not ask for a shell)

Specter ran the read-only indexer query below before this prompt. Use it.

\`\`\`
${h.text}
\`\`\`

**Read the verdict from FULL retained history, not the --days window.** A short
window or a sensor outage makes a long-running alert look brand new; the tool
flags that disagreement when it sees one. Quote the full-history figures.
`;
}
