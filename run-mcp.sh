#!/usr/bin/env bash
# Launcher for the Kali MCP bridge.
#
# Claude Code (or any MCP client) runs this instead of client.py directly.
# It makes sure the Flask API server (server.py) is running, starting it
# detached if needed, then exec()s the stdio MCP client so the client inherits
# this process's stdin/stdout (the MCP channel).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/.venv/bin/python"
SERVER="$HERE/server.py"
CLIENT="$HERE/client.py"
URL="${KALI_API_URL:-http://127.0.0.1:5000}"

LOGDIR="${XDG_STATE_HOME:-$HOME/.local/state}/mcp-kali-server"
mkdir -p "$LOGDIR"

# Fall back to system python if the venv isn't present.
[ -x "$PY" ] || PY="$(command -v python3)"

# Derive the bind host/port from URL so the server we start matches the client.
hostport="${URL#*://}"; hostport="${hostport%%/*}"
host="${hostport%%:*}"
port="${hostport##*:}"
[ "$port" = "$hostport" ] && port=5000

# Start the API server only if it isn't already answering /health.
if ! curl -sf -o /dev/null "$URL/health" 2>/dev/null; then
  setsid "$PY" "$SERVER" --ip "$host" --port "$port" </dev/null >>"$LOGDIR/server.log" 2>&1 &
  echo "$!" > "$LOGDIR/server.pid"
  # Wait up to ~5s for it to come up.
  for _ in $(seq 1 20); do
    curl -sf -o /dev/null "$URL/health" 2>/dev/null && break
    sleep 0.25
  done
fi

# Replace this process with the MCP stdio client.
exec "$PY" "$CLIENT" --server "$URL"
