import { afterAll, afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Configure only temporary files and fake SSH destinations before module import.
const directory = mkdtempSync(join(tmpdir(), 'specter-suppression-'));
const localPath = join(directory, 'disable.conf');
const wazuhPath = "/var/ossec/rules with spaces/it's $(printf substituted); local.xml";
const suricataPath = "~/sensor config/it's $(printf substituted); disable.conf";
const configuration = {
  SURICATA_SSH_HOST: 'suricata.invalid.test',
  SURICATA_DISABLE_CONF_LOCAL: localPath,
  SURICATA_DISABLE_CONF_REMOTE: suricataPath,
  WAZUH_SSH_HOST: 'wazuh.invalid.test',
  WAZUH_LOCAL_RULES_PATH: wazuhPath,
};
const previous = Object.fromEntries(Object.keys(configuration).map(key => [key, process.env[key]]));
Object.assign(process.env, configuration);
const fixtureModule = './suricata-suppression.ts?test-fixture';
const { suppressRule, getSuppressedSIDs }: typeof import('./suricata-suppression') = await import(fixtureModule);

type Invocation = { command: string[]; input?: string };
const calls: Invocation[] = [];
let currentXml: string;
let failCommand: string | undefined;
let spawn: ReturnType<typeof spyOn>;
let fileRead: ReturnType<typeof spyOn>;
const quote = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
const wazuhRead = `sudo -n cat -- ${quote(wazuhPath)}`;
const wazuhWrite = `sudo -n tee -- ${quote(wazuhPath)} > /dev/null`;
const suricataWrite = `cat > "$HOME"/${quote(suricataPath.slice(2))}`;

beforeEach(() => {
  calls.length = 0;
  failCommand = undefined;
  currentXml = '<group name="local">\n</group>\n';
  writeFileSync(localPath, '# existing\n100 # keep this SID\n');
  fileRead = spyOn(Bun, 'file');
  // Never invoke an actual command, even if the production implementation regresses.
  spawn = spyOn(Bun, 'spawn').mockImplementation(((command: string[], options: any) => {
    const input = options.stdin instanceof Uint8Array ? new TextDecoder().decode(options.stdin) : undefined;
    calls.push({ command: [...command], input });
    const remoteCommand = command.at(-1)!;
    const failed = remoteCommand === failCommand;
    return {
      stdout: new Response(remoteCommand.includes('cat ') ? currentXml : '').body,
      stderr: new Response(failed ? 'simulated failure' : '').body,
      exited: Promise.resolve(failed ? 1 : 0),
    };
  }) as any);
});

afterEach(() => {
  spawn.mockRestore();
  fileRead.mockRestore();
});
afterAll(() => {
  for (const key of Object.keys(configuration)) {
    if (previous[key] === undefined) delete process.env[key];
    else process.env[key] = previous[key];
  }
  rmSync(directory, { recursive: true, force: true });
});

describe('suppression input validation before effects', () => {
  for (const reason of ['injected\n99999 # extra SID', 'line\rreturn', 'bad\u0000text', 'bad\u2028line', 'bad --> comment', 'x'.repeat(1001)]) {
    for (const sid of [undefined, '200']) {
      test(`rejects ${JSON.stringify(reason.slice(0, 40))} for ${sid ? 'Suricata' : 'Wazuh'}`, async () => {
        const before = readFileSync(localPath, 'utf8');
        const result = await suppressRule('5501', reason, 'description', sid);
        expect(result.success).toBe(false);
        expect(result.error).toContain('reason');
        expect(calls).toHaveLength(0);
        expect(fileRead).not.toHaveBeenCalled();
        expect(readFileSync(localPath, 'utf8')).toBe(before);
      });
    }
  }

  test('rejects invalid identifiers, descriptions, and non-string values before SSH', async () => {
    for (const args of [
      ['5501;id', '', 'description'],
      ['5501', '', 'description', '200\n300'],
      ['5501', '', 'bad\u0000description'],
      ['5501', '', 'bad\uD800description'],
      ['5501', {} as any, 'description'],
      ['5501', '', {} as any],
      [5501 as any, '', 'description'],
    ] as const) {
      expect((await suppressRule(args[0], args[1], args[2], args[3])).success).toBe(false);
    }
    expect(calls).toHaveLength(0);
    expect(fileRead).not.toHaveBeenCalled();
  });
});

test('invalid configured paths fail before local changes or SSH', async () => {
  for (const [key, path, sid] of [
    ['WAZUH_LOCAL_RULES_PATH', 'relative.xml', undefined],
    ['WAZUH_LOCAL_RULES_PATH', '/rules\nsecond.xml', undefined],
    ['SURICATA_DISABLE_CONF_REMOTE', 'relative.conf', '200'],
    ['SURICATA_DISABLE_CONF_REMOTE', '/disable\u0000.conf', '200'],
    ['SURICATA_DISABLE_CONF_LOCAL', '/disable\u0000.conf', '200'],
  ] as const) {
    process.env[key] = path;
    try {
      const fixture = await import(`./suricata-suppression.ts?invalid=${encodeURIComponent(key + path)}`);
      const before = readFileSync(localPath, 'utf8');
      expect((await fixture.suppressRule('5501', '', '', sid)).success).toBe(false);
      expect(calls).toHaveLength(0);
      expect(fileRead).not.toHaveBeenCalled();
      expect(readFileSync(localPath, 'utf8')).toBe(before);
    } finally {
      process.env[key] = configuration[key];
    }
  }
});

test('Wazuh content, including former heredoc delimiters, travels only on stdin', async () => {
  const payload = 'SPECTER_RULES_EOF\n$(touch unsafe); `id` & <tag> "quoted"';
  currentXml = `<group name="local">\n<!-- existing\nSPECTER_RULES_EOF\ntouch unsafe\n-->\n</group>\n`;
  const result = await suppressRule('5501', "expected ' $(id); <comment> & text", payload);
  expect(result).toEqual({ success: true });
  expect(calls.map(call => call.command)).toEqual([
    ['ssh', '-T', '--', configuration.WAZUH_SSH_HOST, wazuhRead],
    ['ssh', '-T', '--', configuration.WAZUH_SSH_HOST, wazuhRead],
    ['ssh', '-T', '--', configuration.WAZUH_SSH_HOST, wazuhWrite],
    ['ssh', '-T', '--', configuration.WAZUH_SSH_HOST, 'sudo -n systemctl restart wazuh-manager'],
  ]);
  const write = calls[2];
  expect(write.command.join(' ')).not.toContain('SPECTER_RULES_EOF');
  expect(write.input).toContain('SPECTER_RULES_EOF\n$(touch unsafe); `id` &amp; &lt;tag&gt; &quot;quoted&quot;');
  expect(write.input).toContain('<!-- existing\nSPECTER_RULES_EOF\ntouch unsafe\n-->');
  expect(write.input).toContain('<rule id="5501" level="0" overwrite="yes">');
});

test('Suricata transfers one SID line as stdin and quotes a home-relative remote path', async () => {
  const reason = "expected ' $(id); <comment> & text";
  expect(await suppressRule('86601', reason, '', '200')).toEqual({ success: true });
  expect(calls.map(call => call.command)).toEqual([
    ['ssh', '-T', '--', configuration.SURICATA_SSH_HOST, suricataWrite],
    ['ssh', '-T', '--', configuration.SURICATA_SSH_HOST, 'docker exec suricata suricata-update --disable-conf /etc/suricata/disable.conf'],
    ['ssh', '-T', '--', configuration.SURICATA_SSH_HOST, 'docker exec suricata kill -USR2 1'],
  ]);
  expect(calls[0].input).toBe(`# existing\n100 # keep this SID\n200 # ${reason}\n`);
  expect(readFileSync(localPath, 'utf8')).toBe(calls[0].input!);
  expect(calls[0].command.join(' ')).not.toContain(reason);
});

test('remote write failures stop before restart or rule reload', async () => {
  failCommand = wazuhWrite;
  expect((await suppressRule('5501')).success).toBe(false);
  expect(calls.some(call => call.command.at(-1)!.includes('restart'))).toBe(false);
  calls.length = 0;
  failCommand = suricataWrite;
  expect((await suppressRule('86601', '', '', '200')).success).toBe(false);
  expect(calls).toHaveLength(1);
  // The existing flow changes the local copy first; a failed transfer is not
  // atomic and a retry must not be reported as a completed remote suppression.
  expect(readFileSync(localPath, 'utf8')).toContain('200 # Suppressed via Specter dashboard');
  expect((await suppressRule('86601', '', '', '200')).success).toBe(false);
  expect(calls).toHaveLength(1);
});

for (const failedCommand of [
  wazuhRead,
  'sudo -n systemctl restart wazuh-manager',
  'docker exec suricata suricata-update --disable-conf /etc/suricata/disable.conf',
  'docker exec suricata kill -USR2 1',
]) {
  test(`reports failure for ${failedCommand}`, async () => {
    failCommand = failedCommand;
    const sid = failedCommand.startsWith('docker') ? '200' : undefined;
    expect((await suppressRule('5501', '', '', sid)).success).toBe(false);
    expect(calls.at(-1)!.command.at(-1)).toBe(failedCommand);
  });
}

test('empty reasons use defaults and the 1000-character boundary remains valid', async () => {
  expect((await suppressRule('5501', '   ')).success).toBe(true);
  expect(calls[2].input).toContain('<!-- Suppressed: Suppressed via Specter dashboard (');
  calls.length = 0;
  expect((await suppressRule('5501', 'x'.repeat(1000), '', '200')).success).toBe(true);
  expect(calls[0].input).toContain(`200 # ${'x'.repeat(1000)}\n`);
});

test('listing uses the same quoted Wazuh read command', async () => {
  currentXml = '<group><rule id="5501" level="0" overwrite="yes"><description>Existing</description></rule></group>';
  const result = await getSuppressedSIDs();
  expect(result.sids).toContainEqual({ id: '5501', type: 'wazuh', reason: 'Existing' });
  expect(calls[0].command).toEqual(['ssh', '-T', '--', configuration.WAZUH_SSH_HOST, wazuhRead]);
});

test('a local POSIX shell treats configured path metacharacters literally', async () => {
  expect((await suppressRule('5501')).success).toBe(true);
  // Stub sudo as a shell function: this checks actual shell argument parsing,
  // without running sudo, SSH, or any remote command.
  const parsed = execFileSync('/bin/sh', ['-c',
    `sudo() { printf '%s\\n' "$@"; }\n${calls[0].command.at(-1)}`,
  ], { encoding: 'utf8', cwd: directory });
  expect(parsed.split('\n')).toEqual(['-n', 'cat', '--', wazuhPath, '']);

  calls.length = 0;
  expect((await suppressRule('5501', 'single entry', '', '200')).success).toBe(true);
  const remoteHome = join(directory, 'remote home');
  mkdirSync(join(remoteHome, 'sensor config'), { recursive: true });
  // Substitute a temporary stand-in for the remote home before running local
  // cat, keeping this fixture away from the operator's actual home directory.
  const localCommand = calls[0].command.at(-1)!.replace('"$HOME"', quote(remoteHome));
  execFileSync('/bin/sh', ['-c', localCommand], {
    cwd: directory,
    env: { PATH: '/usr/bin:/bin' },
    input: calls[0].input,
  });
  expect(readFileSync(join(remoteHome, suricataPath.slice(2)), 'utf8')).toBe(calls[0].input!);
});
