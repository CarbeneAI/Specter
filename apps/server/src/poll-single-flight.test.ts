import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/poll-single-flight.ts', import.meta.url));
describe('actual Wazuh polling is single-flight', () => {
  for (const scenario of [
    'overlap-fetch', 'overlap-response', 'overlap-scoring', 'storage-reentry', 'repeated-start',
    'fetch-error', 'http-error', 'json-error', 'mapping-error', 'scorer-error', 'callback-error', 'empty-response',
  ]) {
    test(scenario, async () => {
      const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], { stdout: 'pipe', stderr: 'pipe' });
      const deadline = setTimeout(() => child.kill(), 8000);
      try {
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
        ]);
        expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
      } finally { clearTimeout(deadline); }
    }, 10000);
  }
});
