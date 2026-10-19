import { afterAll, beforeAll, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

let directory: string;
const fixture = fileURLToPath(new URL('../test-fixtures/response-deadline.ts', import.meta.url));
function openssl(...args: string[]) {
  const result = Bun.spawnSync(['openssl', ...args], { cwd: directory });
  if (result.exitCode !== 0) throw new Error(result.stderr.toString());
}
beforeAll(() => {
  directory = mkdtempSync(join(tmpdir(), 'specter-response-deadline-'));
  writeFileSync(join(directory, 'ca.cnf'), '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=Deadline fixture CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
  writeFileSync(join(directory, 'server.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n');
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', 'ca.key', '-out', 'ca.pem', '-config', 'ca.cnf');
  openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Deadline fixture', '-keyout', 'server.key', '-out', 'server.csr');
  openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', 'server.ext', '-out', 'server.pem');
}, 15000);
afterAll(() => { if (directory) rmSync(directory, { recursive: true, force: true }); });

for (const scenario of [
  'models-body-timeout', 'models-header-timeout', 'models-error-cancel', 'models-slow-success', 'models-empty',
  'search-body-timeout', 'search-error-body-timeout', 'search-slow-success', 'search-http-error',
  'poll-body-timeout', 'poll-error-cancel', 'poll-slow-success', 'models-native-30s',
]) {
  test(scenario, async () => {
    const env: NodeJS.ProcessEnv = { ...process.env, NO_PROXY: '*' };
    for (const key of Object.keys(env)) {
      if (/proxy/i.test(key) && key !== 'NO_PROXY') delete env[key];
      if (/^(WAZUH_|NODE_TLS_|NODE_EXTRA_CA|SSL_CERT|ANTHROPIC|CLAUDE|OLLAMA)/.test(key)) delete env[key];
    }
    const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario, directory], { env, stdout: 'pipe', stderr: 'pipe' });
    const deadline = setTimeout(() => child.kill(), scenario === 'models-native-30s' ? 42000 : 7000);
    try {
      const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect({ code, output: code === 0 ? '' : stdout + stderr }).toEqual({ code: 0, output: '' });
    } finally { clearTimeout(deadline); }
  }, scenario === 'models-native-30s' ? 45000 : 9000);
}
