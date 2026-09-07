#!/usr/bin/env bash
# curl-examples.sh — Direct MCP JSON-RPC calls to the mcp-ssh server.
#
# Demonstrates all 6 MCP tools over the Streamable HTTP transport using curl:
#   1. ssh_list_servers
#   2. ssh_list_allowed_commands
#   3. ssh_execute_command
#   4. ssh_check_connection
#   5. ssh_download_file
#   6. ssh_upload_file
#
# The Streamable HTTP transport is stateful: a session must be initialized
# before tools can be called.  This script performs the full handshake
# (GET /mcp -> initialize -> notifications/initialized) and then sends
# tools/call requests with the Mcp-Session-Id header.
#
# Environment variables:
#   MCP_SSH_URL      MCP endpoint      (default: http://localhost:9080/mcp;
#                                       the Docker image listens on 8080,
#                                       compose maps it to host port 9080)
#   MCP_SSH_API_KEY  API key           (required; sent as X-API-Key header)
#   MCP_SSH_SERVER   Target server id  (default: web-server)
#
# Usage:
#   export MCP_SSH_API_KEY="your-api-key"
#   ./curl-examples.sh
#
# Note: the default per-IP rate limit is 60 requests/minute — this script
# stays well below that.

set -euo pipefail

MCP_URL="${MCP_SSH_URL:-http://localhost:9080/mcp}"
API_KEY="${MCP_SSH_API_KEY:-}"
SERVER="${MCP_SSH_SERVER:-web-server}"

if [[ -z "$API_KEY" ]]; then
    echo "ERROR: set MCP_SSH_API_KEY (the raw API key configured for your client)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

# Pretty-print JSON if python3 is available, otherwise print raw.
_pretty() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -m json.tool 2>/dev/null || cat
    else
        cat
    fi
}

# Extract the SSE "data:" payload lines and join them into one JSON document.
_sse_data() {
    sed -n 's/^data:[[:space:]]*//p' | tr -d '\n'
}

# GET /mcp to obtain a session ID (returned as the mcp-session-id header).
_get_session_id() {
    local sid
    sid="$(curl -sS -D - -o /dev/null \
        -H "Accept: text/event-stream" \
        -H "X-API-Key: $API_KEY" \
        "$MCP_URL" | tr -d '\r' | awk 'tolower($1) == "mcp-session-id:" { print $2 }')"
    if [[ -z "$sid" ]]; then
        echo "ERROR: server did not return an mcp-session-id header" >&2
        exit 1
    fi
    printf '%s' "$sid"
}

# POST a JSON-RPC message to /mcp within the given session.
# Arguments: $1 = session id, $2 = JSON payload
# Prints the JSON-RPC response (extracted from the SSE body).
_post_jsonrpc() {
    local sid="$1" payload="$2"
    curl -sS -X POST "$MCP_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "X-API-Key: $API_KEY" \
        -H "Mcp-Session-Id: $sid" \
        -d "$payload" | _sse_data
}

# Full initialize handshake; echoes the session id.
_init_session() {
    local sid
    sid="$(_get_session_id)"

    _post_jsonrpc "$sid" '{
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "curl-examples", "version": "1.0.0" }
        }
    }' > /dev/null

    # Notifications take no id and return HTTP 202 with an empty body.
    _post_jsonrpc "$sid" '{
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }' > /dev/null || true

    printf '%s' "$sid"
}

# Call an MCP tool.  Arguments: $1 = session id, $2 = tool name, $3 = arguments JSON object
_call_tool() {
    local sid="$1" tool="$2" args="$3"
    _post_jsonrpc "$sid" "$(printf '{
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {
            "name": "%s",
            "arguments": %s
        }
    }' "$tool" "$args")"
}

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

main() {
    echo "=== mcp-ssh curl examples ==="
    echo "Endpoint: $MCP_URL"
    echo

    echo "--- Initializing MCP session ---"
    local sid
    sid="$(_init_session)"
    echo "Session established."
    echo

    echo "--- 1. ssh_list_servers ---"
    _call_tool "$sid" "ssh_list_servers" '{}' | _pretty
    echo

    echo "--- 2. ssh_list_allowed_commands ($SERVER) ---"
    _call_tool "$sid" "ssh_list_allowed_commands" "{\"server_name\": \"$SERVER\"}" | _pretty
    echo

    echo "--- 3. ssh_execute_command ($SERVER: uptime) ---"
    _call_tool "$sid" "ssh_execute_command" "{\"server_name\": \"$SERVER\", \"command\": \"uptime\"}" | _pretty
    echo

    echo "--- 3b. ssh_execute_command with sudo=true (succeeds only where sudo_allowed permits it) ---"
    _call_tool "$sid" "ssh_execute_command" "{\"server_name\": \"$SERVER\", \"command\": \"systemctl status ssh\", \"sudo\": true}" | _pretty
    echo

    echo "--- 4. ssh_check_connection ($SERVER) ---"
    _call_tool "$sid" "ssh_check_connection" "{\"server_name\": \"$SERVER\"}" | _pretty
    echo

    echo "--- 5. ssh_download_file ($SERVER:/etc/hostname) ---"
    _call_tool "$sid" "ssh_download_file" "{\"server_name\": \"$SERVER\", \"remote_path\": \"/etc/hostname\"}" | _pretty
    echo

    echo "--- 6. ssh_upload_file ($SERVER:/tmp/hello-mcp-ssh.txt) ---"
    _call_tool "$sid" "ssh_upload_file" "{\"server_name\": \"$SERVER\", \"remote_path\": \"/tmp/hello-mcp-ssh.txt\", \"content\": \"Hello from mcp-ssh!\", \"permissions\": \"0644\"}" | _pretty
    echo
}

main
