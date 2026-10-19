# Specter - Development Guide

## Project Overview

Specter is a real-time SIEM security dashboard that connects to Wazuh and Suricata, displays live alerts, and includes an AI chat panel (Claude) that can autonomously search historical alerts.

## Tech Stack

- **Runtime**: Bun (NOT Node.js)
- **Language**: TypeScript
- **Frontend**: Vue 3 + Vite + Tailwind CSS (CarbeneAI dark theme)
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

Explicitly set `WAZUH_DASHBOARD_USER=alert-reader` as the onboarding example.
This account is not created by Specter: provision it or choose your own
least-privileged account with Dashboard console-proxy access to query
`wazuh-alerts-*`. Its password belongs in `WAZUH_DASHBOARD_PASSWORD`. An unset or
empty username retains the existing `admin` compatibility fallback. See
[Wazuh HTTPS trust](docs/wazuh-tls.md).

Copy `.env.example` to `.env` and configure. Required:
- `WAZUH_DASHBOARD_URL` - Your Wazuh server URL
- `WAZUH_DASHBOARD_PASSWORD` - Password for the configured Wazuh account

AI configuration is optional for alert ingestion and deterministic scoring.
`TRIAGE_PROVIDER` selects the Cloud toggle's backend:

- `claude` (default): set `CLAUDE_CLI_SSH_HOST` to a host with an authenticated
  Claude CLI. CLI/SSH failure falls back to the configured Ollama service.
- `ollama`: set `OLLAMA_URL` and `OLLAMA_MODEL` for your local service.
- `anthropic`: configure `ANTHROPIC_API_KEY` (or `WAZUH_PAI_API_KEY`) for the paid
  Messages API. An Anthropic key is not required by the other providers.

The Local toggle explicitly selects Ollama. Optional historical correlation uses
`QUERY_INDEXER_PATH` and `QUERY_INDEXER_ENV`; both must be absolute paths on the
SSH host. Tilde-prefixed and relative paths are rejected.

## Key Architecture Notes

- Server polls Wazuh Indexer every 30s via Dashboard API proxy (`/api/console/proxy`)
- WebSocket streams alerts to all connected clients in real-time
- AI chat uses Claude tool use to autonomously search Wazuh Indexer
- Alert suppression requires SSH access to Suricata/Wazuh hosts
- Wazuh polling and direct search verify HTTPS by default; configure private trust
  with `WAZUH_CA_FILE`, never a process-wide TLS bypass. See `docs/wazuh-tls.md`.

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
