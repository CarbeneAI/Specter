# Specter Architecture

## System Overview

The Cloud toggle follows `TRIAGE_PROVIDER` (default `claude`); the Local toggle
selects Ollama. Only the Anthropic backend runs a Wazuh search tool loop and
records investigations in the ledger. The CLI backend fetches optional history
on the server before building its prompt. Ollama receives the supplied alert
context without that lookup.

```
┌─────────────────────────────────────────────────────┐
│                    Browser                          │
│  ┌─────────────────┐    ┌──────────────────────┐   │
│  │   Alert Feed    │    │    AI Chat Panel     │   │
│  │  (Vue 3 + WS)   │◄──►│ (provider routing)  │   │
│  └─────────────────┘    └──────────────────────┘   │
└─────────────────────┬───────────────────┬───────────┘
                      │ WebSocket         │ HTTP POST
                      ▼                   ▼
         ┌────────────────────────────────────────┐
         │         Specter Server (Bun)           │
         │  ┌──────────┐  ┌─────────────────────┐│
         │  │ WS Hub   │  │   HTTP API          ││
         │  └──────────┘  └─────────────────────┘│
         │  ┌──────────────────────────────────┐  │
         │  │         alert-ingest.ts          │  │
         │  │  Polls Wazuh every 30s via       │  │
         │  │  Dashboard API proxy             │  │
         │  └──────────────────────────────────┘  │
         └──────────┬───────────────┬─────────────┘
                    │               │
                    ▼               ▼
         ┌──────────────┐  ┌───────────────────┐
         │ Wazuh SIEM   │  │   AI providers    │
         │ (OpenSearch) │  │ CLI / Ollama / API│
         └──────────────┘  └───────────────────┘
```

## Components

### Server (`apps/server/`)

**`index.ts`** - Main Bun server
- HTTP endpoints for REST API
- WebSocket hub for real-time streaming
- Broadcasts new alerts to all connected clients

**`alert-ingest.ts`** - Alert ingestion service
- Primary: polls Wazuh Indexer via Dashboard API proxy every 30s
- Fallback: watches JSONL file (`WAZUH_ALERTS_PATH`) for file-based ingest
- Accepts HTTP POST to `/alerts/ingest` for webhook-based ingest
- Keeps last 500 alerts in memory

**`pai-client.ts`** - AI chat with tool use
- Routes CLI/Ollama requests to `triage-provider.ts`
- Sends Anthropic-provider messages to the Messages API
- Provides `search_wazuh_alerts` tool for autonomous Indexer queries
- Bounded tool-use loop of search → analysis
- Formats alert context as markdown for system prompt

**`triage-provider.ts`** - Provider selection and CLI/Ollama requests
- Defaults to Claude CLI over SSH; `CLAUDE_CLI_SSH_HOST` is required for this path
- Injects optional server-fetched history into the CLI prompt using `alert-history.ts`
- Falls back to Ollama after a failed CLI/SSH call
- Sends Ollama requests to the configured local service

**`suricata-suppression.ts`** - Rule suppression via SSH
- Suricata: appends to `disable.conf`, SCPs to remote, runs `suricata-update`
- Wazuh: modifies `local_rules.xml` via SSH, restarts manager

**`types.ts`** - Shared TypeScript interfaces

### Client (`apps/client/`)

**`App.vue`** - Root component
- Split-screen layout with resizable divider
- Manages suppressed/dismissed alert state
- Coordinates between alert feed and chat panel

**`components/AlertStats.vue`** - Stats bar
- Shows Critical/High/Medium/Low counts
- Clickable badges to filter by severity
- Live/Disconnected indicator
- Suppressed and dismissed counts

**`components/AlertFeed.vue`** - Alert list
- Renders filtered alerts
- Computes filter options from current alerts

**`components/AlertRow.vue`** - Single alert row
- Severity indicator bar (left edge)
- Rule level badge, MITRE IDs, agent name, timestamp
- Dismiss (X) - hides this specific alert instance
- Suppress (bell-off) - hides all alerts from this rule/SID

**`components/ChatPanel.vue`** - AI chat
- Quick action buttons (Analyze, Remediation, IOCs, MITRE, Related)
- Chat history with user/assistant bubbles
- Selected alert shown as context indicator

**`composables/useWebSocket.ts`** - WebSocket client
- Auto-reconnects on disconnect
- Ping/pong keepalive every 30s
- URL from `VITE_WS_URL` or current-origin `/stream` with `ws:`/`wss:`
- Shared [endpoint and network policy](network-boundary.md) with API callers

**`composables/usePAIChat.ts`** - Chat state
- Manages message history
- Sends to `/chat` endpoint with alert context

## Data Flow

### Alert Ingestion Flow

```
Wazuh Indexer
  → HTTP GET (Dashboard API proxy, every 30s)
  → alert-ingest.ts (normalizes, assigns IDs)
  → in-memory store (last 500 alerts)
  → WebSocket broadcast to all clients
  → Vue reactive state in browser
```

### AI Analysis Flow

```
User selects alert + sends message
  → usePAIChat.ts POST /chat
  → pai-client.ts resolves the requested provider
    → claude: optional server-side history → Claude CLI over SSH
      → failed CLI/SSH call: Ollama fallback
    → ollama: supplied alert context → Ollama
    → anthropic: alert context → Messages API + search_wazuh_alerts tool loop
      → searchWazuhAlerts() → Wazuh Indexer → tool_result
  → Response displayed in chat panel
```

## Wazuh API Access Pattern

Specter accesses Wazuh Indexer via the Dashboard API proxy:

```
GET/POST https://wazuh-host/api/console/proxy?path=wazuh-alerts-*%2F_search&method=POST
Headers:
  Authorization: Basic base64(user:password)
  osd-xsrf: true
  Content-Type: application/json
Body: OpenSearch query DSL
```

This avoids the need to open Indexer port 9200 externally.

## Severity Mapping

| Wazuh Rule Level | Specter Severity | Color |
|-----------------|-----------------|-------|
| 12-15 | Critical | #f7768e (red) |
| 7-11 | High | #e0af68 (orange) |
| 3-6 | Medium | #bb9af7 (purple) |
| 0-2 | Low | #9ece6a (green) |
