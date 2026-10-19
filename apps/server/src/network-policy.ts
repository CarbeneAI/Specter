/** Request boundaries reduce browser/LAN exposure; they do not authenticate a caller. */
export interface NetworkPolicy {
  hostname: string;
  port: number;
  clientHostname: string;
  clientPort: number;
  allowedOrigin: string;
  allowedHosts: ReadonlySet<string>;
}

function authorityHostname(authority: string | null): string | null {
  // Reject ambiguous authority syntax before URL normalization. In particular,
  // userinfo, multiple Host values, and forwarded headers never establish trust.
  if (!authority || !/^(?:\[[a-f\d:.]+\]|[a-z\d.-]+)(?::\d{1,5})?$/i.test(authority)) return null;
  try {
    const hostname = new URL(`http://${authority}`).hostname;
    if (!hostname.startsWith('[') && !hostname.split('.').every(label => /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label))) return null;
    const rawHost = authority.startsWith('[') ? authority.slice(0, authority.indexOf(']') + 1) : authority.split(':')[0];
    return hostname === rawHost.toLowerCase() ? hostname : null;
  } catch {
    return null;
  }
}

function port(value: string | undefined, fallback: string, name: string): number {
  const text = value || fallback;
  if (!/^\d+$/.test(text) || Number(text) > 65535) throw new Error(`${name} must be a port from 0 to 65535`);
  return Number(text);
}

function bindHost(value: string | undefined, name: string): string {
  const host = value || '127.0.0.1';
  const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  if (!authorityHostname(authority) || authorityHostname(authority) !== authority.toLowerCase()) {
    throw new Error(`${name} must be a hostname or IP address without a port`);
  }
  return host.replace(/^\[|\]$/g, '');
}

export function readNetworkPolicy(env: Record<string, string | undefined> = process.env): NetworkPolicy {
  const clientPort = port(env.CLIENT_PORT, '5173', 'CLIENT_PORT');
  const origin = env.CORS_ALLOWED_ORIGIN || `http://127.0.0.1:${clientPort}`;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new Error('CORS_ALLOWED_ORIGIN must be one absolute http(s) origin');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) {
    throw new Error('CORS_ALLOWED_ORIGIN must be one http(s) origin without credentials, path, query, or fragment');
  }

  const allowedHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
  for (const value of (env.SPECTER_ALLOWED_HOSTS || '').split(',').filter(Boolean)) {
    const host = value.trim();
    const parsed = authorityHostname(host);
    if (!parsed || parsed !== host.toLowerCase()) {
      throw new Error('SPECTER_ALLOWED_HOSTS must contain exact hostnames or bracketed IPv6 addresses without ports');
    }
    allowedHosts.add(parsed);
  }

  return {
    hostname: bindHost(env.SPECTER_API_HOST, 'SPECTER_API_HOST'),
    port: port(env.PORT, '4001', 'PORT'),
    clientHostname: bindHost(env.SPECTER_CLIENT_HOST, 'SPECTER_CLIENT_HOST'),
    clientPort,
    allowedOrigin: url.origin,
    allowedHosts,
  };
}

export function requestIsAllowed(request: { headers: Headers }, policy: NetworkPolicy): boolean {
  const hostname = authorityHostname(request.headers.get('Host'));
  if (!hostname || !policy.allowedHosts.has(hostname)) return false;
  const origin = request.headers.get('Origin');
  const site = request.headers.get('Sec-Fetch-Site');
  // Browser resource GETs can omit Origin. Reject explicit cross-origin metadata
  // without blocking same-origin proxy requests or headerless command-line clients.
  if (origin === null && (site === 'cross-site' || site === 'same-site')) return false;
  // No-Origin CLI and proxy traffic remains supported. A trusted authenticated
  // reverse proxy and firewall are still required before exposing the API remotely.
  return origin === null || origin === policy.allowedOrigin;
}
