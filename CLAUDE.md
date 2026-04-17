# Specter - Development Guide

## Project Overview

Specter is a real-time SIEM security dashboard that connects to Wazuh and Suricata, displays live alerts, and includes an AI chat panel (Claude) that can autonomously search historical alerts.

## Tech Stack

- **Runtime**: Bun (NOT Node.js)
- **Language**: TypeScript
- **Frontend**: Vue 3 + Vite + Tailwind CSS (Tokyo Night theme)
- **Backend**: Bun HTTP + WebSocket server
- **AI**: Anthropic Claude API (with tool use for Wazuh search)

## Project Structure

```
Specter/
├── apps/
│   ├── server/          # Bun HTTP + WebSocket server
│   │   └── src/
│   │       ├── index.ts              # Main server (HTTP + WebSocket)
│   │       ├── types.ts              # Shared TypeScript interfaces
│   │       ├── alert-ingest.ts       # Wazuh poller + JSONL watcher
│   │       ├── pai-client.ts         # Claude AI chat with tool use
│   │       └── suricata-suppression.ts  # SSH-based rule suppression
│   └── client/          # Vue 3 Vite app
│       └── src/
│           ├── App.vue              # Main layout, split panels
│           ├── types.ts             # Client-side types
│           ├── components/          # Vue components
│           └── composables/         # Vue composables
├── .env.example         # Environment variable template
├── manage.sh            # Start/stop script
└── specter.service      # Systemd unit file
```

## Development

```bash
# Install dependencies
cd apps/server && bun install
cd apps/client && bun install

# Start both (requires .env configured)
./manage.sh start

# Start individually
cd apps/server && bun run dev
cd apps/client && bun run dev
```

## Environment Variables

Copy `.env.example` to `.env` and configure. Required:
- `WAZUH_DASHBOARD_URL` - Your Wazuh server URL
- `WAZUH_DASHBOARD_PASSWORD` - Your Wazuh admin password
- `ANTHROPIC_API_KEY` - For AI chat features

## Key Architecture Notes

- Server polls Wazuh Indexer every 30s via Dashboard API proxy (`/api/console/proxy`)
- WebSocket streams alerts to all connected clients in real-time
- AI chat uses Claude tool use to autonomously search Wazuh Indexer
- Alert suppression requires SSH access to Suricata/Wazuh hosts
- `NODE_TLS_REJECT_UNAUTHORIZED=0` needed for Wazuh self-signed certs

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /alerts/recent | Get recent alerts |
| GET | /alerts/stats | Alert counts by severity |
| POST | /alerts/ingest | Ingest alerts via HTTP (n8n webhook) |
| POST | /chat | Send message to AI analyst |
| GET | /chat/prompts | Get quick prompt templates |
| POST | /alerts/search | Search Wazuh Indexer |
| POST | /alerts/suppress | Suppress a rule |
| GET | /alerts/suppressed | List suppressed rules |
| WS | /stream | WebSocket alert stream |

## Severity Levels (Wazuh)

| Level | Severity |
|-------|----------|
| 12+ | Critical |
| 7-11 | High |
| 3-6 | Medium |
| 0-2 | Low |
