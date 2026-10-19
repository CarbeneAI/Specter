import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/poll-commit.ts', import.meta.url));
describe('Wazuh cursor commits after storage', () => {
  for (const scenario of [
    'initial-score-retry', 'committed-score-retry', 'partial-scoring',
    'subscriber-error', 'notification-reentry', 'public-interleave',
    'file-interleave', 'retention-order', 'empty-retains-cursor',
  ]) test(scenario, async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], { stdout: 'pipe', stderr: 'pipe' });
    const deadline = setTimeout(() => child.kill(), 8000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
      ]);
      expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
    } finally { clearTimeout(deadline); }
  }, 10000);
});
