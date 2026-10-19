import { expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

for (const scenario of ['vite', 'vite-preview', 'vite-command']) test(`actual ${scenario} HTTP and WebSocket proxy preserves the boundary`, async () => {
  const fixture = fileURLToPath(new URL('../../../server/test-fixtures/network.ts', import.meta.url));
  const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], { stdout: 'pipe', stderr: 'pipe' });
  const deadline = setTimeout(() => child.kill(), 12000);
  try {
    const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({ exitCode: 0, output: '' });
  } finally { clearTimeout(deadline); }
}, 15000);
