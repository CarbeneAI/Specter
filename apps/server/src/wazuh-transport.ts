import { X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

let warnedInsecure = false;

/** Resolve only Wazuh's trust settings; never change process-wide HTTPS policy. */
export async function wazuhTransport(rawUrl: string): Promise<{ url: URL; tls: Bun.TLSOptions }> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('WAZUH_DASHBOARD_URL must be an absolute HTTPS URL.');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('WAZUH_DASHBOARD_URL must use HTTPS without credentials, query, or fragment.');
  }

  const insecure = process.env.WAZUH_INSECURE_TLS ?? '';
  if (!['', 'false', 'true'].includes(insecure)) {
    throw new Error('WAZUH_INSECURE_TLS must be true or false.');
  }
  const caPath = process.env.WAZUH_CA_FILE;
  if (insecure === 'true' && caPath) {
    throw new Error('WAZUH_CA_FILE cannot be combined with WAZUH_INSECURE_TLS=true.');
  }

  const tls: Bun.TLSOptions = { rejectUnauthorized: insecure !== 'true' };
  if (caPath) {
    if (!isAbsolute(caPath)) throw new Error('WAZUH_CA_FILE must be an absolute path to a PEM CA bundle.');
    let ca: string;
    try {
      ca = await readFile(caPath, 'utf8');
    } catch {
      throw new Error('Cannot read WAZUH_CA_FILE. Check its path and file permissions.');
    }
    // Reject malformed files locally instead of letting an unusable trust setting
    // silently fall back to the runtime's defaults. Bundles may contain CA certs only.
    const blocks = ca.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    try {
      if (!blocks?.length || blocks.reduce((rest, block) => rest.replace(block, ''), ca).trim()) throw new Error();
      for (const block of blocks) if (!new X509Certificate(block).ca) throw new Error();
    } catch {
      throw new Error('WAZUH_CA_FILE must contain only valid PEM CA certificates.');
    }
    tls.ca = ca;
  }
  if (insecure === 'true' && !warnedInsecure) {
    console.warn('[wazuh-client] WAZUH_INSECURE_TLS=true: Wazuh server identity is not verified. Configure WAZUH_CA_FILE to restore verification.');
    warnedInsecure = true;
  }
  return { url, tls };
}
