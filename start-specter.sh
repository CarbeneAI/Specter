#!/usr/bin/env bash
# Foreground launcher for Specter (server + client) under systemd.
#
# Why this exists instead of `manage.sh start`: manage.sh backgrounds both
# children and then returns, so with Type=simple systemd sees the unit exit
# immediately and the service flaps. This stays in the foreground and lets
# KillMode=control-group reap both children. Mirrors start-harbinger.sh.
#
# It also exports .env explicitly. `bun run dev` is `bun --watch src/index.ts`
# with no --env-file, so without this the server dies at startup with
# "WAZUH_DASHBOARD_URL environment variable is required".
set -uo pipefail
DIR=/home/cgarrison/Specter
set -a
[ -f "$DIR/.env" ] && . "$DIR/.env"
set +a
CLIENT_PORT="${CLIENT_PORT:-5173}"
export PATH="/home/cgarrison/.bun/bin:$PATH"
# Wazuh dashboard uses a self-signed cert on the LAN.
export NODE_TLS_REJECT_UNAUTHORIZED=0

cd "$DIR/apps/server"
bun --watch src/index.ts &

cd "$DIR/apps/client"
bun ./node_modules/.bin/vite --port "$CLIENT_PORT" --host 0.0.0.0 &

# Exit (and let systemd restart) if either process dies.
wait -n
