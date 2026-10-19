/** Same-origin defaults; VITE_* values are explicit build-time overrides. */
export interface EndpointEnv { VITE_API_URL?: string; VITE_WS_URL?: string }
export interface EndpointLocation { protocol: string; host: string }

export function resolveEndpoints(
  env: EndpointEnv = import.meta.env,
  location: EndpointLocation = window.location,
): { api: string; ws: string } {
  return {
    api: (env.VITE_API_URL || '/api').replace(/\/+$/, ''),
    ws: env.VITE_WS_URL || `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/stream`,
  };
}
