import { afterEach, describe, expect, test } from 'bun:test';
import {
  getTriageProvider,
  resolveTriageProvider,
} from './triage-provider';

const ORIGINAL = process.env.TRIAGE_PROVIDER;

afterEach(() => {
  if (ORIGINAL === undefined) delete process.env.TRIAGE_PROVIDER;
  else process.env.TRIAGE_PROVIDER = ORIGINAL;
});

describe('getTriageProvider', () => {
  test('defaults to claude when unset', () => {
    delete process.env.TRIAGE_PROVIDER;
    expect(getTriageProvider()).toBe('claude');
  });

  test('accepts claude, ollama, anthropic', () => {
    process.env.TRIAGE_PROVIDER = 'ollama';
    expect(getTriageProvider()).toBe('ollama');
    process.env.TRIAGE_PROVIDER = 'anthropic';
    expect(getTriageProvider()).toBe('anthropic');
    process.env.TRIAGE_PROVIDER = 'claude';
    expect(getTriageProvider()).toBe('claude');
  });

  test('unknown values fall back to claude', () => {
    process.env.TRIAGE_PROVIDER = 'not-a-provider';
    expect(getTriageProvider()).toBe('claude');
  });
});

describe('resolveTriageProvider', () => {
  test('client ollama always wins', () => {
    process.env.TRIAGE_PROVIDER = 'claude';
    expect(resolveTriageProvider('ollama')).toBe('ollama');
    process.env.TRIAGE_PROVIDER = 'anthropic';
    expect(resolveTriageProvider('ollama')).toBe('ollama');
  });

  test('client anthropic (Cloud) follows TRIAGE_PROVIDER env', () => {
    process.env.TRIAGE_PROVIDER = 'claude';
    expect(resolveTriageProvider('anthropic')).toBe('claude');
    process.env.TRIAGE_PROVIDER = 'anthropic';
    expect(resolveTriageProvider('anthropic')).toBe('anthropic');
    process.env.TRIAGE_PROVIDER = 'ollama';
    expect(resolveTriageProvider('anthropic')).toBe('ollama');
  });

  test('undefined client provider follows env default', () => {
    delete process.env.TRIAGE_PROVIDER;
    expect(resolveTriageProvider(undefined)).toBe('claude');
  });
});
