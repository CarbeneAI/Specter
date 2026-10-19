import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/network.ts', import.meta.url));
describe('real HTTP and WebSocket boundary', () => {
  for (const scenario of ['default-bind', 'invalid-config', 'denials', 'configured', 'websockets']) {
    test(scenario, async () => {
      const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], { stdout: 'pipe', stderr: 'pipe' });
      const deadline = setTimeout(() => child.kill(), 8000);
      try {
        const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
        expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
      } finally { clearTimeout(deadline); }
    }, 10000);
  }
});
