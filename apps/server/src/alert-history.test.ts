/**
 * Tests for validateRemotePaths() in alert-history.ts.
 *
 * These exist because of a real outage: QUERY_INDEXER_ENV was set to
 * `~/PAI/.claude/.env`. The tilde was expanded by the LOCAL shell on srv-apps
 * (Linux, HOME=/home/cgarrison) but the path is used on the SSH target (macOS,
 * HOME=/Users/cgarrison). The file did not exist there, `. <file> 2>/dev/null`
 * swallowed the error, QueryIndexer.ts exited 2 for a missing password, and
 * every triage reported "Historical correlation — still unavailable" with no
 * indication that the cause was a config path rather than an absent history.
 */

import { describe, test, expect } from 'bun:test';
import { validateRemotePaths } from './alert-history';

describe('validateRemotePaths', () => {
  test('accepts absolute remote paths', () => {
    expect(
      validateRemotePaths(
        '/Users/cgarrison/.claude/skills/WazuhDashboard/tools/QueryIndexer.ts',
        '/Users/cgarrison/PAI/.claude/.env',
      ),
    ).toBeNull();
  });

  test('rejects a tilde in the env file — the exact 2026-09-23 outage', () => {
    const problem = validateRemotePaths(
      '/Users/cgarrison/.claude/skills/WazuhDashboard/tools/QueryIndexer.ts',
      '~/PAI/.claude/.env',
    );
    expect(problem).not.toBeNull();
    expect(problem).toContain('QUERY_INDEXER_ENV');
    expect(problem).toContain("'~'");
  });

  test('rejects a tilde in the indexer path', () => {
    const problem = validateRemotePaths('~/.claude/tools/QueryIndexer.ts', '/Users/c/.env');
    expect(problem).toContain('QUERY_INDEXER_PATH');
  });

  test('rejects a relative path', () => {
    expect(validateRemotePaths('tools/QueryIndexer.ts', '/Users/c/.env'))
      .toContain('absolute');
  });

  test('reports which variable is unset', () => {
    expect(validateRemotePaths(undefined, '/Users/c/.env')).toBe('QUERY_INDEXER_PATH is not set');
    expect(validateRemotePaths('/a/b.ts', undefined)).toBe('QUERY_INDEXER_ENV is not set');
  });

  test('the problem string names the offending value so it is actionable', () => {
    const problem = validateRemotePaths('/a/b.ts', '~/PAI/.claude/.env');
    expect(problem).toContain('~/PAI/.claude/.env');
  });
});
