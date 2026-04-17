#!/bin/bash
# Specter Security Dashboard Manager

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PORT="${PORT:-4001}"
CLIENT_PORT="${CLIENT_PORT:-5173}"

# Load .env if present
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

case "${1:-}" in
    start)
        # Check if already running
        if lsof -Pi :$SERVER_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "Specter already running at http://localhost:$CLIENT_PORT"
            exit 0
        fi

        echo "Starting Specter server on port $SERVER_PORT..."
        # Start server (NODE_TLS_REJECT_UNAUTHORIZED=0 for Wazuh self-signed certs)
        cd "$SCRIPT_DIR/apps/server"
        NODE_TLS_REJECT_UNAUTHORIZED=0 bun run dev >/tmp/specter-server.log 2>&1 &
        SERVER_PID=$!

        # Wait for server
        for i in {1..15}; do
            curl -s http://localhost:$SERVER_PORT/health >/dev/null 2>&1 && break
            sleep 1
        done

        echo "Starting Specter client on port $CLIENT_PORT..."
        # Start client
        cd "$SCRIPT_DIR/apps/client"
        bun run dev >/tmp/specter-client.log 2>&1 &
        CLIENT_PID=$!

        # Wait for client
        for i in {1..15}; do
            curl -s http://localhost:$CLIENT_PORT >/dev/null 2>&1 && break
            sleep 1
        done

        echo "Specter running at http://localhost:$CLIENT_PORT"
        echo "Server logs: /tmp/specter-server.log"
        echo "Client logs: /tmp/specter-client.log"

        # Cleanup on exit
        cleanup() {
            kill $SERVER_PID $CLIENT_PID 2>/dev/null
            exit 0
        }
        trap cleanup INT TERM
        wait $SERVER_PID $CLIENT_PID
        ;;

    stop)
        echo "Stopping Specter..."
        for port in $SERVER_PORT $CLIENT_PORT; do
            if [[ "$OSTYPE" == "darwin"* ]]; then
                PIDS=$(lsof -ti :$port 2>/dev/null)
            else
                PIDS=$(lsof -ti :$port 2>/dev/null || fuser -n tcp $port 2>/dev/null | awk '{print $2}')
            fi
            [ -n "$PIDS" ] && kill -9 $PIDS 2>/dev/null
        done

        # Kill remaining bun processes for this project
        ps aux | grep -E "bun.*(specter)" | grep -v grep | awk '{print $2}' | while read PID; do
            [ -n "$PID" ] && kill -9 $PID 2>/dev/null
        done

        echo "Specter stopped"
        ;;

    restart)
        echo "Restarting Specter..."
        "$0" stop 2>/dev/null
        sleep 1
        exec "$0" start
        ;;

    status)
        if lsof -Pi :$SERVER_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "Running at http://localhost:$CLIENT_PORT"
            echo "API at http://localhost:$SERVER_PORT"
        else
            echo "Not running"
        fi
        ;;

    logs)
        echo "=== Server Logs ==="
        tail -50 /tmp/specter-server.log 2>/dev/null || echo "No server logs found"
        echo ""
        echo "=== Client Logs ==="
        tail -20 /tmp/specter-client.log 2>/dev/null || echo "No client logs found"
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start    Start Specter dashboard"
        echo "  stop     Stop Specter dashboard"
        echo "  restart  Restart Specter dashboard"
        echo "  status   Check if running"
        echo "  logs     View recent logs"
        exit 1
        ;;
esac
