import { describe, expect, test } from 'bun:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../test-fixtures/alert-ingest.ts', import.meta.url));

// Each fixture owns the ingestion singleton, scorer, timers, and environment in a
// child process. This keeps the HTTP integration suite's server state untouched.
describe('alert identity across ingestion paths', () => {
  for (const scenario of ['retention', 'concurrent', 'mixed-sources', 'failed-scoring']) {
    test(scenario, async () => {
      const child = Bun.spawn([process.execPath, '--no-env-file', fixture, scenario], {
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const deadline = setTimeout(() => child.kill(), 8000);
      try {
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ]);
        expect({ exitCode, output: exitCode === 0 ? '' : stdout + stderr }).toEqual({
          exitCode: 0,
          output: '',
        });
      } finally {
        clearTimeout(deadline);
      }
    }, 10000);
  }
});
