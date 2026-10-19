/**
 * Alert Suppression
 * Manages suppressing noisy alerts from the dashboard:
 * - Suricata IDS alerts: disable SID via disable.conf + suricata-update
 * - Wazuh alerts: set rule level to 0 via local_rules.xml overwrite
 *
 * Requires SSH access to your Suricata and Wazuh hosts.
 * Configure via environment variables:
 *   SURICATA_SSH_HOST=user@suricata-host
 *   WAZUH_SSH_HOST=user@wazuh-host
 *   SURICATA_DISABLE_CONF_REMOTE=~/path/to/disable.conf (optional)
 *   WAZUH_LOCAL_RULES_PATH=/var/ossec/etc/rules/local_rules.xml (optional)
 */

// Suricata suppression host (e.g. "user@192.168.1.100")
const SURICATA_SSH_HOST = process.env.SURICATA_SSH_HOST || '';
const SURICATA_DISABLE_CONF_LOCAL = process.env.SURICATA_DISABLE_CONF_LOCAL || './suricata-disable.conf';
const SURICATA_DISABLE_CONF_REMOTE = process.env.SURICATA_DISABLE_CONF_REMOTE || '~/suricata/config/disable.conf';

// Wazuh suppression host (e.g. "user@192.168.1.200")
const WAZUH_SSH_HOST = process.env.WAZUH_SSH_HOST || '';
const WAZUH_LOCAL_RULES = process.env.WAZUH_LOCAL_RULES_PATH || '/var/ossec/etc/rules/local_rules.xml';

/**
 * Run a command via Bun.spawn and return stdout/stderr
 */
async function runCommand(cmd: string[], input?: string): Promise<{ success: boolean; stdout: string; stderr: string }> {
  try {
    const proc = Bun.spawn(cmd, {
      stdout: 'pipe',
      stderr: 'pipe',
      // Configuration content is data, never part of the remote shell command.
      // Commands without a payload do not inherit the caller's stdin.
      stdin: input === undefined ? 'ignore' : new TextEncoder().encode(input),
    });

    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);

    const exitCode = await proc.exited;

    return {
      success: exitCode === 0,
      stdout: stdout.trim(),
      stderr: stderr.trim(),
    };
  } catch (error) {
    return {
      success: false,
      stdout: '',
      stderr: error instanceof Error ? error.message : 'Command failed',
    };
  }
}

/** Quote one path for the POSIX shell used by SSH; expand only a leading ~/. */
function remotePath(path: string): string {
  if ((!path.startsWith('/') && !path.startsWith('~/')) || /[\u0000-\u001f\u007f\u2028\u2029]/u.test(path)) {
    throw new Error('Remote suppression path must be absolute or start with ~/ and contain no control characters');
  }
  const quote = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
  return path.startsWith('~/') ? `"$HOME"/${quote(path.slice(2))}` : quote(path);
}

function ssh(host: string, command: string, input?: string) {
  return runCommand(['ssh', '-T', '--', host, command], input);
}

// ─── Suricata SID suppression ───────────────────────────────────────

/**
 * Read the current disable.conf and return suppressed SIDs
 */
async function getSuppressedSuricataSIDs(): Promise<{ sid: string; reason: string }[]> {
  try {
    const file = Bun.file(SURICATA_DISABLE_CONF_LOCAL);
    if (!await file.exists()) return [];

    const content = await file.text();
    const sids: { sid: string; reason: string }[] = [];

    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const match = trimmed.match(/^(\d+)\s*(?:#\s*(.*))?$/);
      if (match) {
        sids.push({ sid: match[1], reason: match[2]?.trim() || '' });
      }
    }
    return sids;
  } catch {
    return [];
  }
}

/**
 * Suppress a Suricata rule by SID
 */
async function suppressSuricataSID(
  signatureId: string,
  reason: string
): Promise<{ success: boolean; error?: string }> {
  if (!SURICATA_SSH_HOST) {
    return { success: false, error: 'SURICATA_SSH_HOST environment variable not configured' };
  }

  // Check not already suppressed
  const existing = await getSuppressedSuricataSIDs();
  if (existing.some(s => s.sid === signatureId)) {
    return { success: false, error: `Suricata SID ${signatureId} is already suppressed` };
  }

  // Append to local disable.conf
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const comment = reason || `Suppressed via Specter dashboard (${timestamp})`;
  const entry = `${signatureId} # ${comment}\n`;

  const file = Bun.file(SURICATA_DISABLE_CONF_LOCAL);
  const content = await file.exists() ? await file.text() : '';
  const newContent = content.endsWith('\n') ? content + entry : content + '\n' + entry;
  await Bun.write(SURICATA_DISABLE_CONF_LOCAL, newContent);
  console.log(`[Suppress] Appended SID ${signatureId} to local disable.conf`);

  // Transfer the configuration through stdin, without SCP's remote path syntax.
  const transferResult = await ssh(
    SURICATA_SSH_HOST, `cat > ${remotePath(SURICATA_DISABLE_CONF_REMOTE)}`, newContent,
  );
  if (!transferResult.success) {
    return { success: false, error: `Remote disable.conf write failed: ${transferResult.stderr}` };
  }

  // suricata-update
  const updateResult = await ssh(
    SURICATA_SSH_HOST,
    'docker exec suricata suricata-update --disable-conf /etc/suricata/disable.conf',
  );
  if (!updateResult.success) {
    return { success: false, error: `suricata-update failed: ${updateResult.stderr}` };
  }

  // Reload rules
  const reloadResult = await ssh(SURICATA_SSH_HOST, 'docker exec suricata kill -USR2 1');
  if (!reloadResult.success) {
    return { success: false, error: `Rule reload failed: ${reloadResult.stderr}` };
  }

  console.log(`[Suppress] Suricata SID ${signatureId} suppressed and rules reloaded`);
  return { success: true };
}

// ─── Wazuh rule suppression ─────────────────────────────────────────

/**
 * Get currently suppressed Wazuh rules from local_rules.xml
 */
async function getSuppressedWazuhRules(): Promise<{ ruleId: string; description: string }[]> {
  if (!WAZUH_SSH_HOST) return [];

  const result = await ssh(WAZUH_SSH_HOST, `sudo -n cat -- ${remotePath(WAZUH_LOCAL_RULES)}`);
  if (!result.success) return [];

  const rules: { ruleId: string; description: string }[] = [];
  // Match rules with level="0" and overwrite="yes"
  const ruleRegex = /<rule\s+id="(\d+)"\s+level="0"\s+overwrite="yes">\s*<description>(.*?)<\/description>/gs;
  let match;
  while ((match = ruleRegex.exec(result.stdout)) !== null) {
    rules.push({ ruleId: match[1], description: match[2] });
  }
  return rules;
}

/**
 * Suppress a Wazuh rule by setting its level to 0 in local_rules.xml
 */
async function suppressWazuhRule(
  ruleId: string,
  description: string,
  reason: string
): Promise<{ success: boolean; error?: string }> {
  if (!WAZUH_SSH_HOST) {
    return { success: false, error: 'WAZUH_SSH_HOST environment variable not configured' };
  }

  // Check not already suppressed
  const existing = await getSuppressedWazuhRules();
  if (existing.some(r => r.ruleId === ruleId)) {
    return { success: false, error: `Wazuh rule ${ruleId} is already suppressed` };
  }

  // Read current local_rules.xml
  const readResult = await ssh(WAZUH_SSH_HOST, `sudo -n cat -- ${remotePath(WAZUH_LOCAL_RULES)}`);
  if (!readResult.success) {
    return { success: false, error: `Failed to read local_rules.xml: ${readResult.stderr}` };
  }

  // Build the new suppression rule
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const commentReason = reason || 'Suppressed via Specter dashboard';
  const safeDesc = description.replace(/[&<>"']/g, c => {
    const entities: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' };
    return entities[c] || c;
  });

  const newRule = `
  <!-- Suppressed: ${commentReason} (${timestamp}) -->
  <rule id="${ruleId}" level="0" overwrite="yes">
    <description>${safeDesc}</description>
  </rule>`;

  // Insert before closing </group> tag
  let content = readResult.stdout;
  const closingTag = '</group>';
  const insertPos = content.lastIndexOf(closingTag);
  if (insertPos === -1) {
    return { success: false, error: 'Could not find </group> tag in local_rules.xml' };
  }

  content = content.slice(0, insertPos) + newRule + '\n\n' + content.slice(insertPos);

  // Both new and existing XML are opaque stdin. A heredoc delimiter in either
  // source must never turn the remaining content into remote shell commands.
  const writeResult = await ssh(
    WAZUH_SSH_HOST, `sudo -n tee -- ${remotePath(WAZUH_LOCAL_RULES)} > /dev/null`, content,
  );
  if (!writeResult.success) {
    return { success: false, error: `Failed to write local_rules.xml: ${writeResult.stderr}` };
  }
  console.log(`[Suppress] Added rule ${ruleId} level=0 to local_rules.xml`);

  // Restart Wazuh manager to apply
  const restartResult = await ssh(WAZUH_SSH_HOST, 'sudo -n systemctl restart wazuh-manager');
  if (!restartResult.success) {
    return { success: false, error: `Wazuh manager restart failed: ${restartResult.stderr}` };
  }
  console.log(`[Suppress] Wazuh manager restarted, rule ${ruleId} now suppressed`);

  return { success: true };
}

// ─── Public API ─────────────────────────────────────────────────────

export interface SuppressedRule {
  id: string;
  type: 'suricata' | 'wazuh';
  reason: string;
}

/**
 * Get all suppressed rules (both Suricata SIDs and Wazuh rules)
 */
export async function getSuppressedSIDs(): Promise<{ sids: SuppressedRule[]; error?: string }> {
  try {
    const [suricata, wazuh] = await Promise.all([
      getSuppressedSuricataSIDs(),
      getSuppressedWazuhRules(),
    ]);

    const sids: SuppressedRule[] = [
      ...suricata.map(s => ({ id: s.sid, type: 'suricata' as const, reason: s.reason })),
      ...wazuh.map(r => ({ id: r.ruleId, type: 'wazuh' as const, reason: r.description })),
    ];

    return { sids };
  } catch (error) {
    return { sids: [], error: error instanceof Error ? error.message : 'Failed to get suppressed rules' };
  }
}

/**
 * Suppress an alert rule
 * @param ruleId - Wazuh rule ID (e.g. "5501")
 * @param reason - User-provided reason
 * @param description - Rule description (for Wazuh local_rules.xml)
 * @param suricataSid - If present, suppress Suricata SID instead of Wazuh rule
 */
export async function suppressRule(
  ruleId: string,
  reason: string = '',
  description: string = '',
  suricataSid?: string,
): Promise<{ success: boolean; error?: string }> {
  // Validate format
  if (typeof ruleId !== 'string' || !/^\d+$/.test(ruleId)) {
    return { success: false, error: 'Invalid rule ID format - must be numeric' };
  }

  // Validate before reading files, opening SSH, or changing local state. The
  // shared reason must fit one disable.conf line and a valid XML comment.
  if (typeof reason !== 'string' || reason.length > 1000 ||
      /[\u0000-\u001f\u007f\u2028\u2029\uFFFE\uFFFF\uD800-\uDFFF]/u.test(reason) || reason.includes('--')) {
    return { success: false, error: 'Invalid suppression reason: use one line, at most 1000 characters, without control characters or --' };
  }
  if (typeof description !== 'string' || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF\uD800-\uDFFF]/u.test(description)) {
    return { success: false, error: 'Invalid rule description: must be XML-compatible text' };
  }
  if (suricataSid !== undefined && (typeof suricataSid !== 'string' || !/^\d+$/.test(suricataSid))) {
    return { success: false, error: 'Invalid Suricata SID format' };
  }
  try {
    remotePath(suricataSid ? SURICATA_DISABLE_CONF_REMOTE : WAZUH_LOCAL_RULES);
    if (suricataSid && /[\u0000-\u001f\u007f]/u.test(SURICATA_DISABLE_CONF_LOCAL)) {
      throw new Error('Local suppression path must contain no control characters');
    }
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : 'Invalid suppression path' };
  }
  reason = reason.trim();

  // If suricataSid provided, suppress via Suricata disable.conf
  if (suricataSid) {
    return suppressSuricataSID(suricataSid, reason);
  }

  // Otherwise suppress via Wazuh local_rules.xml
  return suppressWazuhRule(ruleId, description || `Rule ${ruleId}`, reason);
}

// Keep backward compat alias
export const suppressSuricataRule = suppressRule;
