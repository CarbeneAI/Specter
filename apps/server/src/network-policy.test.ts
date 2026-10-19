import { describe, expect, test } from 'bun:test';
import { readNetworkPolicy, requestIsAllowed } from './network-policy';

const policy = readNetworkPolicy({});
const allowed = (headers: Record<string, string>) => requestIsAllowed({ headers: new Headers(headers) }, policy);

describe('exact network admission', () => {
  test('loopback defaults and configurable ports/binds', () => {
    expect(policy.hostname).toBe('127.0.0.1');
    expect(policy.clientHostname).toBe('127.0.0.1');
    expect(policy.port).toBe(4001);
    expect(policy.clientPort).toBe(5173);
    expect(policy.allowedOrigin).toBe('http://127.0.0.1:5173');
    const custom = readNetworkPolicy({ SPECTER_API_HOST: '::1', SPECTER_CLIENT_HOST: '0.0.0.0', PORT: '4801', CLIENT_PORT: '5417' });
    expect(custom.hostname).toBe('::1');
    expect(custom.clientHostname).toBe('0.0.0.0');
    expect(custom.allowedOrigin).toBe('http://127.0.0.1:5417');
    expect(custom.port).toBe(4801);
  });
  test('headerless clients and exact browser origin', () => {
    expect(allowed({ Host: 'localhost:4001' })).toBe(true);
    expect(allowed({ Host: '[::1]:4001', Origin: policy.allowedOrigin })).toBe(true);
    expect(allowed({ Host: '127.0.0.1:4001', 'Sec-Fetch-Site': 'same-origin' })).toBe(true);
  });
  test('foreign/ambiguous authorities and origins fail closed', () => {
    for (const Host of ['', 'evil.test', 'localhost.evil.test', '127.0.0.2', 'localhost,evil.test', 'user@localhost', 'localhost:99999', '0x7f000001']) {
      expect(allowed({ Host, Origin: policy.allowedOrigin })).toBe(false);
    }
    for (const Origin of ['null', 'https://evil.test', policy.allowedOrigin + '/', policy.allowedOrigin + '.evil.test', policy.allowedOrigin + ' https://evil.test']) {
      expect(allowed({ Host: 'localhost', Origin })).toBe(false);
    }
    expect(allowed({ Host: 'localhost', 'Sec-Fetch-Site': 'cross-site' })).toBe(false);
    expect(allowed({ Host: 'localhost', 'Sec-Fetch-Site': 'same-site' })).toBe(false);
  });
  test('configuration rejects wildcards, credentials, paths and malformed binds/ports', () => {
    for (const value of ['*.example.test', '.example.test', 'example.test:443', 'https://example.test', 'user@example.test']) {
      expect(() => readNetworkPolicy({ SPECTER_ALLOWED_HOSTS: value })).toThrow();
    }
    for (const value of ['*', 'null', 'file:///tmp', 'https://user:pass@ok.test', 'https://ok.test/path', 'https://ok.test/?a=b', 'https://ok.test/#hash']) {
      expect(() => readNetworkPolicy({ CORS_ALLOWED_ORIGIN: value })).toThrow();
    }
    for (const key of ['PORT', 'CLIENT_PORT']) for (const value of ['-1', '65536', '4001junk', '1.5']) {
      expect(() => readNetworkPolicy({ [key]: value })).toThrow();
    }
    for (const key of ['SPECTER_API_HOST', 'SPECTER_CLIENT_HOST']) for (const value of ['*', 'https://localhost', 'localhost:4001']) {
      expect(() => readNetworkPolicy({ [key]: value })).toThrow();
    }
  });
});
