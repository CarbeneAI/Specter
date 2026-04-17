# Specter Setup Guide

## Prerequisites

- **Bun** v1.0+ - [Install](https://bun.sh)
- **Wazuh** self-hosted instance with Dashboard API access
- **Anthropic API key** - [Get one](https://console.anthropic.com)
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

```bash
# In .env:
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

Without this key, the server will start but the chat panel will return errors.

## Step 4: Install Dependencies

```bash
cd apps/server && bun install && cd ../..
cd apps/client && bun install && cd ../..
```

## Step 5: Start Specter

```bash
./manage.sh start
```

Open http://localhost:5173

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
curl -X POST http://localhost:4001/alerts/ingest \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-01-01T00:00:00Z","rule":{"level":7,"description":"Test alert","id":"1234"},"agent":{"id":"001","name":"my-server"}}'
```

In n8n, use an HTTP Request node pointing to `http://specter-host:4001/alerts/ingest`.

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
