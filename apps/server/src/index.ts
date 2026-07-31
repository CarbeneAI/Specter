/**
 * Specter - Security Dashboard Server
 * HTTP API + WebSocket server for real-time alert streaming
 */

import type { WazuhAlert, PAIChatMessage } from './types';
import {
  startAlertIngestion,
  getRecentAlerts,
  getAlertStats,
  getFilterOptions,
  filterAlerts,
  addAlerts,
  getScoredAlerts,
} from './alert-ingest';
import type { ScoreBand } from './scorer';
import { sendChatMessage, searchWazuhAlerts, getOllamaModels, QUICK_PROMPTS } from './pai-client';
import type { AIProvider } from './pai-client';
import { suppressSuricataRule, getSuppressedSIDs } from './suricata-suppression';
import { listInvestigations, getInvestigation } from './ledger';

// GET /ledger/:id -- :id must be a well-formed UUID. Validated by regex BEFORE
// getInvestigation() is ever called, so a malformed id short-circuits to 404
// without touching SQLite (defense in depth, mirrors the guard already inside
// ledger.ts's getInvestigation()). Deliberately does NOT match /ledger/:id/share
// or /ledger/share/:token -- share-token routes are out of scope for this build.
const investigationMatch = (pathname: string) =>
  pathname.match(/^\/ledger\/([0-9a-f-]{36})$/i);

const PORT = parseInt(process.env.PORT || '4001');

// Store WebSocket clients
const wsClients = new Set<any>();

// Allowed origin for CORS. Set CORS_ALLOWED_ORIGIN to the URL the dashboard is
// served from. A specific origin (not '*') is required because the client sends
// credentials:include. Defaults to the Vite dev server for a fresh clone.
const ALLOWED_ORIGIN = process.env.CORS_ALLOWED_ORIGIN || 'http://localhost:5173';

// Start alert ingestion with WebSocket broadcast callback
startAlertIngestion((alerts) => {
  // Broadcast each alert to connected WebSocket clients
  alerts.forEach((alert) => {
    const message = JSON.stringify({ type: 'alert', data: alert });
    wsClients.forEach((client) => {
      try {
        client.send(message);
      } catch (err) {
        wsClients.delete(client);
      }
    });
  });

  // Also broadcast updated stats
  const stats = getAlertStats();
  const statsMessage = JSON.stringify({ type: 'stats', data: stats });
  wsClients.forEach((client) => {
    try {
      client.send(statsMessage);
    } catch (err) {
      wsClients.delete(client);
    }
  });
});

// Shape of the POST /chat request body -- narrow on purpose, mirrors the
// fields sendChatMessage() actually consumes.
interface ChatRequestBody {
  message?: string;
  history?: PAIChatMessage[];
  alertContext?: WazuhAlert[];
  sessionId?: string;
  provider?: AIProvider;
  ollamaUrl?: string;
  ollamaModel?: string;
}

// Create Bun server with HTTP and WebSocket support
const server = Bun.serve({
  port: PORT,

  async fetch(req: Request) {
    const url = new URL(req.url);

    // Log authenticated user from Authentik forward-auth headers (injected by Traefik).
    // Traefik strips any forged X-Authentik-* headers before this point.
    const akUser = req.headers.get('X-Authentik-Email') || req.headers.get('X-Authentik-Username') || '<unauthenticated>';
    console.log(`[req] ${req.method} ${url.pathname} user=${akUser}`);

    // CORS: specific origin required when credentials:include is used on the client.
    // Vary: Origin tells CDN/proxy caches that responses differ by origin.
    const origin = req.headers.get('Origin');
    const corsOrigin = origin === ALLOWED_ORIGIN ? ALLOWED_ORIGIN : '';
    const headers: Record<string, string> = {
      'Access-Control-Allow-Origin': corsOrigin || ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Credentials': 'true',
      'Vary': 'Origin',
    };

    // Preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    // Health check
    if (url.pathname === '/health' && req.method === 'GET') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: Date.now() }), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /alerts/recent - Get recent alerts
    if (url.pathname === '/alerts/recent' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '100');
      const alerts = getRecentAlerts(limit);
      return new Response(JSON.stringify(alerts), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /alerts/stats - Get alert statistics
    if (url.pathname === '/alerts/stats' && req.method === 'GET') {
      const stats = getAlertStats();
      return new Response(JSON.stringify(stats), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /alerts/filter-options - Get available filter options
    if (url.pathname === '/alerts/filter-options' && req.method === 'GET') {
      const options = getFilterOptions();
      return new Response(JSON.stringify(options), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /alerts/filter - Filter alerts
    if (url.pathname === '/alerts/filter' && req.method === 'GET') {
      const severities = url.searchParams.get('severities')?.split(',').filter(Boolean);
      const agents = url.searchParams.get('agents')?.split(',').filter(Boolean);
      const groups = url.searchParams.get('groups')?.split(',').filter(Boolean);
      const limit = parseInt(url.searchParams.get('limit') || '100');

      const alerts = filterAlerts(severities, agents, groups, limit);
      return new Response(JSON.stringify(alerts), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /alerts/scored - Get scored alerts, optionally filtered by band
    if (url.pathname === '/alerts/scored' && req.method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '100');
      const band = url.searchParams.get('band') as ScoreBand | null;
      const alerts = getScoredAlerts(limit, band || undefined);
      return new Response(JSON.stringify(alerts), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // POST /alerts/ingest - Receive alerts from n8n webhook
    if (url.pathname === '/alerts/ingest' && req.method === 'POST') {
      try {
        const body = await req.json();

        // Handle both single alert and array of alerts
        const alertsToAdd = Array.isArray(body) ? body : [body];

        if (alertsToAdd.length === 0) {
          return new Response(
            JSON.stringify({ success: false, error: 'No alerts provided' }),
            { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } }
          );
        }

        const storedAlerts = await addAlerts(alertsToAdd);
        console.log(`Ingested ${storedAlerts.length} alert(s) via HTTP`);

        return new Response(
          JSON.stringify({ success: true, count: storedAlerts.length }),
          { headers: { ...headers, 'Content-Type': 'application/json' } }
        );
      } catch (error) {
        console.error('Ingest error:', error);
        return new Response(
          JSON.stringify({ success: false, error: 'Invalid JSON' }),
          { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } }
        );
      }
    }

    // POST /chat - Send message to AI analyst
    if (url.pathname === '/chat' && req.method === 'POST') {
      try {
        const body = await req.json() as ChatRequestBody;
        const { message, history = [], alertContext, sessionId, provider, ollamaUrl, ollamaModel } = body;

        if (!message) {
          return new Response(
            JSON.stringify({ success: false, error: 'Message required' }),
            { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } }
          );
        }

        const response = await sendChatMessage(message, history, alertContext, sessionId, provider, ollamaUrl, ollamaModel);
        return new Response(JSON.stringify(response), {
          headers: { ...headers, 'Content-Type': 'application/json' },
        });
      } catch (error) {
        console.error('Chat error:', error);
        return new Response(
          JSON.stringify({ success: false, error: 'Internal error' }),
          { status: 500, headers: { ...headers, 'Content-Type': 'application/json' } }
        );
      }
    }

    // GET /chat/prompts - Get quick prompt templates
    if (url.pathname === '/chat/prompts' && req.method === 'GET') {
      return new Response(JSON.stringify(QUICK_PROMPTS), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /ledger - List recent investigations (read-only, no mutation surface)
    if (url.pathname === '/ledger' && req.method === 'GET') {
      const rawLimit = parseInt(url.searchParams.get('limit') || '50');
      const limit = Math.min(Math.max(1, Number.isNaN(rawLimit) ? 50 : rawLimit), 200);
      const investigations = listInvestigations(limit);
      return new Response(JSON.stringify({ investigations }), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /ledger/:id - Replay a single investigation (permalink; UUID only)
    // SCOPE NOTE: share-token routes (/ledger/:id/share, /ledger/share/:token)
    // are out of scope for this build -- do not add them here.
    if (url.pathname.startsWith('/ledger/') && req.method === 'GET') {
      const idMatch = investigationMatch(url.pathname);
      // Malformed/non-UUID-shaped id (e.g. /ledger/not-a-uuid), or any deeper
      // path like /ledger/:id/share: 404, never a 500 and never a SQL lookup.
      const investigation = idMatch ? getInvestigation(idMatch[1]) : null;
      if (!investigation) {
        return new Response(JSON.stringify({ error: 'Not found' }), {
          status: 404,
          headers: { ...headers, 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ investigation }), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // POST /alerts/search - Search Wazuh Indexer
    if (url.pathname === '/alerts/search' && req.method === 'POST') {
      try {
        const body = await req.json() as Record<string, unknown>;
        const result = await searchWazuhAlerts(body as any);
        return new Response(JSON.stringify(result), {
          headers: { ...headers, 'Content-Type': 'application/json' },
        });
      } catch (error) {
        console.error('Search error:', error);
        return new Response(
          JSON.stringify({ results: [], total: 0, error: 'Invalid request' }),
          { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } }
        );
      }
    }

    // POST /alerts/suppress - Suppress an alert rule (Suricata SID or Wazuh rule)
    if (url.pathname === '/alerts/suppress' && req.method === 'POST') {
      try {
        const body = await req.json() as Record<string, unknown>;
        const ruleId = body.ruleId;
        const reason = body.reason;
        const description = body.description;
        const suricataSid = body.suricataSid;

        if (!ruleId) {
          return new Response(
            JSON.stringify({ success: false, error: 'ruleId is required' }),
            { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } }
          );
        }

        const result = await suppressSuricataRule(
          String(ruleId),
          String(reason || ''),
          String(description || ''),
          suricataSid ? String(suricataSid) : undefined,
        );
        const status = result.success ? 200 : 400;
        return new Response(JSON.stringify(result), {
          status,
          headers: { ...headers, 'Content-Type': 'application/json' },
        });
      } catch (error) {
        console.error('Suppress error:', error);
        return new Response(
          JSON.stringify({ success: false, error: 'Invalid request' }),
          { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } }
        );
      }
    }

    // GET /alerts/suppressed - Get list of suppressed SIDs
    if (url.pathname === '/alerts/suppressed' && req.method === 'GET') {
      const result = await getSuppressedSIDs();
      return new Response(JSON.stringify(result), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // GET /settings/ollama-models - Fetch available Ollama models
    if (url.pathname === '/settings/ollama-models' && req.method === 'GET') {
      const ollamaUrl = url.searchParams.get('ollamaUrl') || 'http://localhost:11434';
      const models = await getOllamaModels(ollamaUrl);
      return new Response(JSON.stringify({ models }), {
        headers: { ...headers, 'Content-Type': 'application/json' },
      });
    }

    // WebSocket upgrade
    if (url.pathname === '/stream') {
      const success = server.upgrade(req);
      if (success) {
        return undefined;
      }
    }

    // Default response
    return new Response('Specter Security Dashboard Server', {
      headers: { ...headers, 'Content-Type': 'text/plain' },
    });
  },

  websocket: {
    open(ws) {
      console.log('WebSocket client connected');
      wsClients.add(ws);

      // Send recent alerts on connection
      const alerts = getRecentAlerts(50);
      const stats = getAlertStats();

      ws.send(JSON.stringify({ type: 'initial', data: alerts }));
      ws.send(JSON.stringify({ type: 'stats', data: stats }));
    },

    message(ws, message) {
      // Handle ping/pong or filter requests
      try {
        const data = JSON.parse(String(message));
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
        } else if (data.type === 'filter') {
          const { severities, agents, groups, limit } = data;
          const alerts = filterAlerts(severities, agents, groups, limit);
          ws.send(JSON.stringify({ type: 'filtered', data: alerts }));
        }
      } catch (err) {
        console.error('Invalid WebSocket message:', err);
      }
    },

    close(ws) {
      console.log('WebSocket client disconnected');
      wsClients.delete(ws);
    },

    // @ts-ignore - Bun's websocket handler supports an 'error' callback at
    // runtime; the installed bun-types WebSocketHandler<T> doesn't declare it.
    error(ws: any, error: unknown) {
      console.error('WebSocket error:', error);
      wsClients.delete(ws);
    },
  },
});

console.log(`Specter Dashboard Server running on http://localhost:${server.port}`);
console.log(`WebSocket endpoint: ws://localhost:${server.port}/stream`);
console.log(`Health check: http://localhost:${server.port}/health`);
