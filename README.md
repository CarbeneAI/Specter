# Specter

**Real-Time SIEM Dashboard with AI-Powered Alert Analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bun](https://img.shields.io/badge/Runtime-Bun-black)](https://bun.sh)
[![Vue 3](https://img.shields.io/badge/Frontend-Vue%203-42b883)](https://vuejs.org)

Specter is a real-time security dashboard that connects to your Wazuh SIEM and Suricata IDS. It streams live alerts with severity-based color coding and includes an AI chat panel (Claude) that can autonomously search your historical alerts to provide context-aware threat analysis.

## Features

- **Live Alert Streaming** - WebSocket-based real-time alert feed from Wazuh Indexer (polls every 30s)
- **Severity Color Coding** - Tokyo Night dark theme with Critical/High/Medium/Low visual hierarchy
- **AI Security Analyst** - Claude-powered chat that autonomously searches Wazuh for historical context
- **Alert Suppression** - Suppress noisy Suricata SIDs or Wazuh rules directly from the UI
- **Alert Filtering** - Filter by severity, agent, and rule group
- **Resizable Split-Screen** - Drag to resize the alert feed and chat panel
- **MITRE ATT&CK** - Displays MITRE technique IDs inline on each alert
- **Compliance Tags** - PCI DSS, HIPAA, GDPR, NIST 800-53 tags on alerts
- **HTTP Ingest** - Accept alerts via POST endpoint (useful with n8n webhooks)

## Screenshots

_Screenshots coming soon_

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Bun |
| Frontend | Vue 3 + Vite + Tailwind CSS |
| Backend | Bun HTTP + WebSocket server |
| AI | Anthropic Claude API (tool use) |
| Theme | Tokyo Night dark |
| Icons | Lucide Vue |

## Requirements

- [Bun](https://bun.sh) v1.0+
- Wazuh SIEM instance (self-hosted)
- [Anthropic API key](https://console.anthropic.com) (for AI chat)
- SSH access to Suricata/Wazuh hosts (optional, for rule suppression)

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/CarbeneAI/Specter.git
cd Specter
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
WAZUH_DASHBOARD_URL=https://your-wazuh-server
WAZUH_DASHBOARD_PASSWORD=your-admin-password
ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Install dependencies

```bash
cd apps/server && bun install
cd ../client && bun install
cd ../..
```

### 4. Start Specter

```bash
./manage.sh start
```

Open http://localhost:5173

## Configuration

See [docs/setup.md](docs/setup.md) for complete setup instructions including:
- Connecting to your Wazuh instance
- Configuring SSH for rule suppression
- Setting up as a systemd service
- Production deployment behind a reverse proxy

## How AI Analysis Works

When you click an alert and use the chat panel:

1. The selected alert is included as context in the system prompt
2. Claude can call `search_wazuh_alerts` tool to query your Wazuh Indexer for historical data
3. Up to 3 tool call iterations for deep correlation
4. Quick actions: Analyze, Remediation, Related alerts, IOCs, MITRE mapping

## Alert Suppression

Two suppression mechanisms:

- **Suricata SID**: Updates `disable.conf` via SCP, runs `suricata-update`, reloads rules
- **Wazuh Rule**: Adds `level="0" overwrite="yes"` to `local_rules.xml`, restarts Wazuh manager

Requires `SURICATA_SSH_HOST` and `WAZUH_SSH_HOST` env vars with SSH key auth configured.

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/alerts/recent?limit=100` | Recent alerts |
| GET | `/alerts/stats` | Counts by severity |
| GET | `/alerts/filter?severities=critical,high` | Filtered alerts |
| POST | `/alerts/ingest` | Ingest alert(s) via HTTP |
| POST | `/chat` | AI chat message |
| GET | `/chat/prompts` | Quick prompt templates |
| POST | `/alerts/search` | Search Wazuh Indexer |
| POST | `/alerts/suppress` | Suppress a rule |
| GET | `/alerts/suppressed` | List suppressed rules |
| WS | `/stream` | Real-time alert stream |

## Manage Script

```bash
./manage.sh start    # Start dashboard
./manage.sh stop     # Stop dashboard
./manage.sh restart  # Restart
./manage.sh status   # Check if running
./manage.sh logs     # View recent logs
```

## Running as a Service

See [docs/deployment.md](docs/deployment.md) for systemd service setup.

## Contributing

Pull requests welcome. Please open an issue first to discuss major changes.

## License

MIT - see [LICENSE](LICENSE)

---

Built by [CarbeneAI](https://carbene.ai)
