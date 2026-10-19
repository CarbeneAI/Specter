import assert from 'node:assert/strict';

for (const key of ['VITE_API_URL', 'VITE_WS_URL']) delete process.env[key];
Object.assign(globalThis, { window: { location: { origin: 'https://dashboard.example.test', protocol: 'https:', host: 'dashboard.example.test' } } });
const calls: { url: string; credentials: RequestCredentials | undefined }[] = [];
globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  calls.push({ url: String(input), credentials: init?.credentials });
  return Response.json(calls.length === 1 ? { investigations: [] } : { investigation: { id: 'fixture' } });
}) as typeof fetch;
const { useLedger } = await import('../src/composables/useLedger');
const ledger = useLedger();
await ledger.fetchList(7);
await ledger.fetchDetail('fixture');
assert.equal(ledger.error.value, null);
assert.deepEqual(calls, [
  { url: 'https://dashboard.example.test/api/ledger?limit=7', credentials: 'include' },
  { url: '/api/ledger/fixture', credentials: 'include' },
]);
