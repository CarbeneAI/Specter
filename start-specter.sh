#!/usr/bin/env bash
# Foreground launcher for Specter (server + client) under systemd.
#
# Resolve paths from this checkout, including when systemd starts us elsewhere.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    . "$SCRIPT_DIR/.env"
    set +a
fi
CLIENT_PORT="${CLIENT_PORT:-5173}"
SPECTER_CLIENT_HOST="${SPECTER_CLIENT_HOST:-127.0.0.1}"
export PATH="${BUN_INSTALL:-$HOME/.bun}/bin:$PATH"
# Wazuh dashboard uses a self-signed cert on the LAN.
export NODE_TLS_REJECT_UNAUTHORIZED=0

if ! command -v bun >/dev/null 2>&1; then
    echo "Bun not found; install it or set BUN_INSTALL/PATH for the service user." >&2
    exit 127
fi
if ! command -v node >/dev/null 2>&1 || ! node_version="$(node --version)"; then
    echo "Node.js 22 or later not found; Vite requires Node for WebSocket proxy support." >&2
    exit 127
fi
node_major="${node_version#v}"
node_major="${node_major%%.*}"
if [[ ! "$node_major" =~ ^[0-9]+$ ]] || (( node_major < 22 )); then
    echo "Node.js 22 or later is required for Vite." >&2
    exit 1
fi
for app in server client; do
    if [[ ! -d "$SCRIPT_DIR/apps/$app" ]]; then
        echo "Missing application directory: $SCRIPT_DIR/apps/$app" >&2
        exit 1
    fi
done

# Only signal our children; systemd's KillMode=control-group also handles any
# descendants. Never stop unrelated Bun processes or kill by listening port.
server_pid=
client_pid=
# Invoked indirectly by the EXIT trap; older ShellCheck versions cannot follow it.
# shellcheck disable=SC2317,SC2329
cleanup() {
    [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true
    [[ -z "$client_pid" ]] || kill "$client_pid" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap 'cleanup' EXIT
trap 'exit 0' INT TERM

(cd "$SCRIPT_DIR/apps/server" && exec bun --watch src/index.ts) &
server_pid=$!
(cd "$SCRIPT_DIR/apps/client" && exec node ./node_modules/vite/bin/vite.js --port "$CLIENT_PORT" --host "$SPECTER_CLIENT_HOST") &
client_pid=$!

# A child can exit before we start waiting. Check both PIDs so an immediate
# startup failure is not missed by wait -n (also unavailable on Bash 3.2).
while kill -0 "$server_pid" 2>/dev/null && kill -0 "$client_pid" 2>/dev/null; do
    sleep 0.2
done
status=0
if ! kill -0 "$server_pid" 2>/dev/null; then
    wait "$server_pid" || status=$?
else
    wait "$client_pid" || status=$?
fi
# Either child exiting, even successfully, leaves the service incomplete.
# Signal-driven shutdown above stays successful; unexpected exits restart it.
(( status != 0 )) || status=1
exit "$status"
