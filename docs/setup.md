# Specter Setup Guide

## Prerequisites

- **Bun** v1.3.14 (tested) - [Install](https://bun.sh)
- **Node.js** 22+ for Vite (22.22.2 tested)
- **Wazuh** self-hosted instance with Dashboard API access
- Optional for AI analysis: an authenticated Claude CLI reachable over SSH,
  a local Ollama service, or an [Anthropic API key](https://console.anthropic.com)
- Optional: Suricata IDS for SID suppression
- Optional: SSH key auth to Wazuh/Suricata hosts

## Step 1: Clone and Configure

```bash
git clone https://github.com/CarbeneAI/Specter.git
cd Specter
cp .env.example .env
```

## Step 2: Configure Wazuh Connection

Specter connects to Wazuh via the Dashboard API proxy endpoint, which proxies to the Indexer.
This avoids the need for direct access to port 9200 (which is typically localhost-only).

```bash
# In .env:
WAZUH_DASHBOARD_URL=https://your-wazuh-host
WAZUH_DASHBOARD_USER=admin
WAZUH_DASHBOARD_PASSWORD=your-password
```

**Finding your Wazuh Dashboard URL:**
- This is the URL you use to access the Wazuh web UI (e.g., `https://192.168.1.100` or `https://wazuh.example.com`)
- Specter uses the API proxy at `/api/console/proxy` to reach the Indexer

**Self-signed certificates:**
Wazuh typically uses self-signed certificates. Specter automatically disables TLS verification
via `NODE_TLS_REJECT_UNAUTHORIZED=0` when running through `manage.sh`.

## Step 3: Configure AI Chat (Optional)

Alert ingestion and deterministic scoring work without an AI provider. To enable
chat, choose a provider in the root `.env`:

| `TRIAGE_PROVIDER` | Required provider setup |
|-------------------|-------------------------|
| `claude` (default) | `CLAUDE_CLI_SSH_HOST=user@host` with an authenticated Claude CLI on that host |
| `ollama` | A running Ollama service; configure `OLLAMA_URL` and `OLLAMA_MODEL` for your installation |
| `anthropic` | `ANTHROPIC_API_KEY` or `WAZUH_PAI_API_KEY` with access to the paid Messages API |

The Cloud toggle follows `TRIAGE_PROVIDER`; the Local toggle selects Ollama.
The CLI provider also falls back to Ollama if the SSH/CLI call fails. An Anthropic
API key is only needed for the `anthropic` provider.

For CLI triage, set `CLAUDE_CLI_BIN` to the executable path on the SSH host if it
is not `/opt/homebrew/bin/claude`.

For optional historical correlation with the CLI provider, set both `QUERY_INDEXER_PATH` and
`QUERY_INDEXER_ENV` to absolute paths on the SSH host. Do not use `~` or relative
paths. See [the README](../README.md#historical-correlation) for details.

## Step 4: Install Dependencies

```bash
cd apps/server && bun install && cd ../..
cd apps/client && bun install && cd ../..
```

## Step 5: Start Specter

```bash
./manage.sh start
```

Open http://127.0.0.1:5173

Loopback binds and exact browser/Host admission are now the default. Follow
[the network migration guide](network-boundary.md) for custom ports, remote
access, and root `.env` browser build settings.

For a service that runs independently of your terminal, use the foreground
`start-specter.sh` launcher through one of the systemd templates described in
[the deployment guide](deployment.md). It loads the checkout's root `.env`.

## Step 6: Configure Alert Suppression (Optional)

To suppress Suricata or Wazuh rules from the dashboard, you need SSH access to those hosts.

### SSH Key Setup

```bash
# Generate a dedicated SSH key (or use your existing one)
ssh-keygen -t ed25519 -f ~/.ssh/specter_key -C "specter-suppression"

# Copy to Suricata host
ssh-copy-id -i ~/.ssh/specter_key user@suricata-host

# Copy to Wazuh host
ssh-copy-id -i ~/.ssh/specter_key user@wazuh-host
```

### Configure Environment

```bash
# In .env:
SURICATA_SSH_HOST=user@suricata-host
WAZUH_SSH_HOST=user@wazuh-host
```

### Suricata Requirements

Specter runs these commands on the Suricata host:
```bash
docker exec suricata suricata-update --disable-conf /etc/suricata/disable.conf
docker exec suricata kill -USR2 1
```

The SSH user needs permission to run these docker commands.

### Wazuh Requirements

Specter runs these commands on the Wazuh host:
```bash
sudo cat /var/ossec/etc/rules/local_rules.xml
sudo tee /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

The SSH user needs passwordless sudo for these specific commands, or full sudo access.

## Connecting via n8n Webhook

You can push alerts to Specter via HTTP POST instead of (or in addition to) polling Wazuh:

```bash
# POST to ingest endpoint
curl -X POST http://127.0.0.1:4001/alerts/ingest \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-01-01T00:00:00Z","rule":{"level":7,"description":"Test alert","id":"1234"},"agent":{"id":"001","name":"my-server"}}'
```

For n8n on this host, use `http://127.0.0.1:4001/alerts/ingest`. Remote n8n
requires an explicit API bind and exact Host allowlist plus a firewall and
authenticated proxy. Follow [the remote access steps](network-boundary.md#remote-n8n)
before pointing another host at the API. Headerless CLI/n8n calls remain supported.

## Troubleshooting

### "WAZUH_DASHBOARD_URL environment variable is required"
Set `WAZUH_DASHBOARD_URL` in your `.env` file.

### "WAZUH_DASHBOARD_PASSWORD environment variable is required"
Set `WAZUH_DASHBOARD_PASSWORD` in your `.env` file.

### WebSocket not connecting
Ensure the server is running: `./manage.sh status`
Check server logs: `./manage.sh logs`

### No alerts loading
1. Verify Wazuh credentials are correct
2. Check that your Wazuh instance has alerts in the `wazuh-alerts-*` indices
3. Check server logs for poll errors: `./manage.sh logs`

### Suppression failing
1. Verify SSH connectivity: `ssh $SURICATA_SSH_HOST echo ok`
2. Check SSH key is authorized on the remote host
3. Verify the Suricata container name is `suricata` (or adjust the code)
