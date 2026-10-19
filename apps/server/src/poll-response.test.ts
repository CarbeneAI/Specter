import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';
import { cases } from '../test-fixtures/poll-response-cases';

const fixture = fileURLToPath(new URL('../test-fixtures/poll-response.ts', import.meta.url));
describe('production polling validates its complete sample before effects', () => {
  for (const scenario of cases) test(scenario.name, async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario.name], { stdout: 'pipe', stderr: 'pipe' });
    const deadline = setTimeout(() => child.kill(), 8000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
      ]);
      expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
    } finally { clearTimeout(deadline); }
  }, 10000);
});
