import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/wazuh-tls.ts', import.meta.url));
let directory: string;

function openssl(...args: string[]): void {
  const result = Bun.spawnSync(['openssl', ...args], { cwd: directory });
  if (result.exitCode !== 0) throw new Error(result.stderr.toString());
}

beforeAll(() => {
  directory = mkdtempSync(join(tmpdir(), 'specter-tls-'));
  // Disposable keys never leave this temporary directory or enter the repository.
  writeFileSync(join(directory, 'ca.cnf'), `[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=Specter fixture CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n`);
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-keyout', 'ca.key', '-out', 'ca.pem', '-config', 'ca.cnf');
  for (const [name, san] of [['valid', 'IP:127.0.0.1'], ['wrong-host', 'DNS:wrong.example.test']]) {
    writeFileSync(join(directory, `${name}.ext`), `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${san}\n`);
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=TLS fixture',
      '-keyout', `${name}.key`, '-out', `${name}.csr`);
    openssl('x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key',
      '-CAcreateserial', '-days', '1', '-extfile', `${name}.ext`, '-out', `${name}.pem`);
  }
  writeFileSync(join(directory, 'invalid.pem'), 'not a certificate');
}, 15000);

afterAll(() => { if (directory) rmSync(directory, { recursive: true, force: true }); });

describe('Wazuh HTTPS transport', () => {
  for (const scenario of [
    'untrusted-default', 'private-ca', 'hostname-mismatch', 'explicit-insecure',
    'unrelated-https-stays-verified', 'redirect-verified', 'redirect-insecure',
    'http-rejected', 'invalid-ca', 'missing-ca', 'relative-ca', 'non-ca-certificate',
    'invalid-insecure-value', 'conflicting-options', 'url-credentials', 'url-query',
  ]) {
    test(scenario, async () => {
      // Each scenario gets a fresh connection pool and configuration, independent
      // of fetch mocks or TLS settings in other server tests or the operator's .env.
      const env: NodeJS.ProcessEnv = { ...process.env, NO_PROXY: '*' };
      for (const key of Object.keys(env)) {
        if (/^(https?|all|no)_proxy$/i.test(key) && key !== 'NO_PROXY') delete env[key];
        if (['NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR'].includes(key)) delete env[key];
      }
      const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario, directory], {
        stdout: 'pipe', stderr: 'pipe', env,
      });
      const deadline = setTimeout(() => child.kill(), 10000);
      try {
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
        ]);
        expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
        if (scenario === 'url-credentials') {
          expect(stdout + stderr).not.toContain('embedded:password');
        }
      } finally {
        clearTimeout(deadline);
      }
    }, 12000);
  }
});
