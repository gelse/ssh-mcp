# ssh-mcp

A centralized MCP gateway that gives AI agents controlled access to SSH infrastructure over Streamable HTTP.

ssh-mcp runs as a single HTTP service. Multiple AI clients — agents, CI pipelines, dashboards — connect to one gateway. SSH credentials stay on the gateway. Authorization policies, audit logging, and rate limiting are applied centrally before any SSH command executes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker)](https://ghcr.io/gelse/ssh-mcp)
[![MCP](https://img.shields.io/badge/MCP-streamable--HTTP-green.svg)](https://modelcontextprotocol.io/)
[![Security](https://img.shields.io/badge/security-layered--auth-orange.svg)](docs/SECURITY.md)

---

## Table of Contents

- [Architecture](#architecture)
- [Why ssh-mcp?](#why-ssh-mcp)
- [Multi-agent access control](#multi-agent-access-control)
- [The Problem](#the-problem)
- [Use Cases](#use-cases)
- [Security Model](#security-model)
- [Quick Start](#quick-start)
- [MCP Client Configuration](#mcp-client-configuration)
- [Tools](#tools)
- [Configuration](#configuration)
- [Observability](#observability)
- [Configuration API](#configuration-api)
- [Deployment](#deployment)
- [Limitations and Threat Model](#limitations-and-threat-model)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

---

## Architecture

### Local stdio MCP (common pattern)

```text
AI client
   │
   ▼
local MCP process ──► SSH target
```

Each agent runs its own process. SSH credentials live on every machine. No centralized control.

### ssh-mcp (centralized HTTP gateway)

```
AI clients ───────┐
CI agents ────────┼──► ssh-mcp ──► SSH targets
Dashboards ───────┘      │
                         ├─ API-key authentication
                         ├─ per-client authorization
                         ├─ rate limiting
                         ├─ audit logging
                         └─ connection pooling
```

A single deployment serves all clients. Credentials, policies, and logs live in one place.

---

## Why ssh-mcp?

- **Centralized HTTP gateway** — One deployment serves all AI agents, CI pipelines, and dashboards over Streamable HTTP
- **Per-client authorization** — Different API keys grant different command sets on different servers
- **Layered command policies** — Block patterns, dangerous-shell detection, and per-target allowlists work together
- **Centralized SSH access** — SSH credentials live on the gateway, not on every agent's machine
- **Audit trail** — Every command, every client, every result — structured JSONL logs with request tracing
- **Operational resilience** — Connection pooling, circuit breakers, and retry with exponential backoff
- **Observability** — Prometheus metrics and health endpoints for monitoring

---

## Multi-agent access control

Different agents need different permissions. ssh-mcp enforces this at the gateway:

```
monitoring agent  →  API key A  →  read-only commands  →  all servers
deployment agent  →  API key B  →  deploy commands      →  web servers only
database agent    →  API key C  →  db commands           →  database server only
```

```
                  ┌─ monitoring agent (read-only, all servers)
                  ├─ deployment agent (deploy commands, web only)
MCP clients ──────┼─ database agent (db commands, db server only)
                  └─ ...
                         │
                         ▼
                      ssh-mcp
                         │
                  centralized policies
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
             web         db      monitoring
           servers    servers     servers
```

A minimal config demonstrating this setup:

```json
{
  "version": 1,
  "ssh_targets": {
    "web-1": { "host": "10.0.1.10", "username": "deploy" },
    "db-1":  { "host": "10.0.1.20", "username": "dbadmin" }
  },
  "allowed_commands": {
    "default": {
      "web-1": { "allow": ["uptime", "df -h", "free -m"] }
    },
    "api_keys": {
      "deploy-key": {
        "web-1": { "allow": ["systemctl restart app", "deploy *"] }
      },
      "db-key": {
        "db-1": { "allow": ["systemctl restart postgres", "pg_dump *"] }
      }
    }
  }
}
```

---

## The Problem

Most MCP SSH servers run as local stdio processes — one per client, with no shared state, no centralized authorization, and no audit trail. When multiple AI agents, CI pipelines, or dashboards need SSH access, each one independently manages its own SSH keys and runs its own MCP process. This creates:

- **No centralized access control** — every client decides what it can run
- **No audit trail** — commands are invisible to the ops team
- **SSH key sprawl** — keys scattered across every machine running an agent
- **No rate limiting** — a runaway agent can overwhelm a target
- **No connection pooling** — each client opens and closes SSH sessions independently

**ssh-mcp** solves this by deploying a single MCP server as an HTTP gateway. All clients connect to it; it connects to your SSH targets. Authorization, authentication, rate limiting, connection pooling, and audit logging happen in one place.

---

## Use Cases

### Multi-Agent Server Management

Run a team of AI agents with different access levels. The deployment agent can `systemctl restart nginx` on web servers; the monitoring agent can `journalctl` everywhere; the database agent can only run `psql` on the DB server. Each agent authenticates with its own API key; each key has its own permission set.

### CI/CD Pipeline Integration

Point your CI pipeline at ssh-mcp instead of managing SSH keys on every runner. A single API key per pipeline, network-based rules for your CI subnet, and command allowlists ensure your deployment scripts run exactly what they should — nothing more.

### Centralized Log and Config Retrieval

Use [`ssh_download_file`](#ssh_download_file) to pull logs, config files, or database dumps from remote servers without leaving your MCP client. The 8-layer path validation and sandbox root settings ensure file transfers stay within safe boundaries.

### Server Health Dashboards

Build an MCP-powered dashboard that queries `uptime`, `free`, `df`, and `ps` across your fleet. The connection pool reuses SSH sessions, the circuit breaker isolates failing targets, and Prometheus metrics at [`/metrics`](#metrics) feed your existing monitoring stack.

### Compliance and Audit

Every command is logged with structured JSONL: who ran what, on which server, from which IP, whether it was allowed, and how long it took. The `matched_via` field traces exactly which authorization layer made the decision. Config changes are logged separately with before/after state.

---

## Security Model

ssh-mcp applies defense-in-depth at every layer. The full security model is documented in [`docs/SECURITY.md`](docs/SECURITY.md).

**Security boundary:** ssh-mcp adds an authorization, authentication, and auditing layer in front of SSH. It does not replace the permissions of the underlying SSH accounts. If a command is allowed, the SSH user executes it with whatever privileges that account has. The gateway itself should be protected with TLS and network access controls. Logs may contain command output and should be treated accordingly.

### Command Authorization Chain

Commands are evaluated through an **ordered, layered chain**. If any layer denies, the request stops there:

| Layer | What it checks |
|---|---|
| 1. Target validation | Is the server name known? |
| 2. `block_patterns` | Does the command match a blocked regex? |
| 3. Dangerous patterns | Does it contain `$()`, backticks, or newlines? |
| 4. Redirection guard | Do shell redirects target `/dev/`, `/proc/`, `/sys/`? |
| 5. Segmentation | After stripping redirects and splitting on `&&`, `||`, `;`, `\|`, each segment runs the full chain |
| 6. `default` rules | All-client allow/deny rules |
| 7. `api_keys` rules | Per-key allow/deny rules |
| 8. `networks` rules | Per-CIDR allow/deny rules |
| 9. Deny | Implicit fallback |

### Authentication

API keys are sent via `X-API-Key` or `Authorization: Bearer` headers. Keys are hashed with PBKDF2-HMAC-SHA256 (100,000 iterations, random 16-byte salt) and verified with constant-time comparison. Raw keys are never stored.

### Input Sanitization

Commands, target names, and log strings are sanitized before processing: null bytes stripped, control characters removed, NFKC-normalized, and run through [ReDoS protection](docs/SECURITY.md#redos-protection) for `block_patterns`.

### Path Traversal Prevention

SFTP transfers go through 8-layer path validation including null-byte checks, control-character stripping, dot-segment normalization, symlink resolution, and sandbox-root enforcement.

### Rate Limiting

Sliding-window rate limiter per client IP (60 requests / 60 seconds, `/health` exempt). Violations return HTTP 429 with `Retry-After`.

Rate limiting is configurable under `settings.rate_limit`:

```jsonc
"settings": {
  "rate_limit": {
    "enabled": true,                        // set false to disable entirely
    "max_requests_per_minute": 60,          // max requests per client IP in the window
    "window_seconds": 60.0,                 // sliding-window duration
    "cleanup_interval_seconds": 300.0       // expired-entry GC interval
  }
}
```

> **Note:** the rate limiter is built **once at container startup** from the initial config and is **not** rebuilt on config hot-reload. To disable rate limiting you must set `settings.rate_limit.enabled` to `false` in the config present at boot (e.g. `config/ssh-mcp-config.json` in the mounted volume). This is useful for high-volume clients or test suites that issue many requests from a single IP.

---

## Quick Start

### Prerequisites

- Docker with Docker Compose
- An SSH key pair (or per-target passwords) for the servers you want to reach

### 1. Set up the directory

```bash
mkdir -p config logs
ssh-keygen -t ed25519 -f ssh_key -N ""
cp default-config.json config/ssh-mcp-config.json
```

### 2. Add an SSH target

Open `config/ssh-mcp-config.json` and add one target:

```jsonc
{
  "version": 1,
  "ssh_targets": {
    "web-server": {
      "host": "192.168.1.10",
      "port": 22,
      "username": "deploy",
      "private_key": "/app/ssh_key"
    }
  },
  "block_patterns": [ "\\brm\\s+-rf\\b", "\\bdd\\s+if=" ],
  "allowed_commands": {
    "default": [
      { "targets": ["*"], "commands": ["hostname", "uptime", "free", "df", "ps", "ls", "cat"] }
    ]
  },
  "settings": {}
}
```

### 3. Start the server

```bash
docker compose up -d --build
```

### 4. Verify it's running

```bash
curl http://localhost:9080/health
# {"status": "ok", "connection_pool": {...}}
```

### 5. Connect an MCP client

Any MCP client supporting Streamable HTTP can connect. Point it at `http://localhost:9080/mcp` with an API key header. See [MCP Client Configuration](#mcp-client-configuration) for details.

### 6. List servers and run a command

```bash
curl -X POST http://localhost:9080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "ssh_list_servers",
      "arguments": {}
    }
  }'

curl -X POST http://localhost:9080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "ssh_execute_command",
      "arguments": {"server_name": "web-server", "command": "uptime"}
    }
  }'
```

---

## MCP Client Configuration

Any MCP client supporting Streamable HTTP transport can connect. The configuration format varies by client — use the URL and headers below.

| Setting | Value |
|---|---|
| Transport | Streamable HTTP |
| URL | `https://ssh-mcp.example.com/mcp` |
| Authentication | `X-API-Key` header or `Authorization: Bearer` |

### Generic Streamable HTTP Configuration

```json
{
  "mcpServers": {
    "ssh": {
      "url": "http://localhost:9080/mcp",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      }
    }
  }
}
```

### Python Client

```python
import requests

MCP_URL = "https://ssh-mcp.example.com/mcp"
API_KEY = "your-api-key"


def call_tool(name: str, arguments: dict) -> dict:
    response = requests.post(
        MCP_URL,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    response.raise_for_status()
    return response.json()


print(call_tool("ssh_list_servers", {}))
print(call_tool("ssh_execute_command", {
    "server_name": "web-server",
    "command": "uptime",
}))
```

### Raw JSON-RPC

Send tool calls as JSON-RPC `tools/call` requests to `/mcp`:

```bash
curl -X POST http://localhost:9080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "ssh_execute_command",
      "arguments": {"server_name": "web-server", "command": "uptime"}
    }
  }'
```

---

## Tools

All tool calls are JSON-RPC `tools/call` requests to [`/mcp`](#mcp-client-configuration). All tools return a **string** (JSON or plain text).

| Tool | Parameters | Description |
|---|---|---|
| `ssh_list_servers` | *(none)* | List configured SSH targets (host, port, username — no secrets) |
| `ssh_list_allowed_commands` | `server_name` (str) | List commands the current client may run on a target (union of default + api_key + network rules) |
| `ssh_execute_command` | `server_name` (str), `command` (str), `timeout` (int, default 30), `sudo` (bool, default false) | Execute a command over SSH; returns stdout (stderr appended as `[STDERR]`, exit code as `[EXIT: n]`) |
| `ssh_download_file` | `server_name` (str), `remote_path` (str) | Download a file via SFTP; authorization equivalent to `cat <path>` |
| `ssh_upload_file` | `server_name` (str), `remote_path` (str), `content` (str), `permissions` (str, default "0644") | Upload a file via SFTP; authorization equivalent to `tee <path>` |
| `ssh_check_connection` | `server_name` (str), `timeout` (int, default 10) | Check SSH connectivity by running the target's `checkcommand`; returns success flag, output, and exit code |

### Examples

```python
# List available servers
call_tool("ssh_list_servers", {})
# {"web-server": {"host": "192.168.1.10", "port": 22, "username": "deploy"}}

# List what this client can run on web-server
call_tool("ssh_list_allowed_commands", {"server_name": "web-server"})
# ["cat", "df", "du", "free", "grep", "head", "hostname", ...]

# Execute a command
call_tool("ssh_execute_command", {
    "server_name": "web-server",
    "command": "uptime",
})
# " 07:12:33 up 10 days,  2:15,  1 user,  load average: 0.08, 0.03, 0.01"

# Download a file
call_tool("ssh_download_file", {
    "server_name": "web-server",
    "remote_path": "/etc/hostname",
})
# "web-server\n"

# Upload a file
call_tool("ssh_upload_file", {
    "server_name": "web-server",
    "remote_path": "/tmp/backup.sql",
    "content": "CREATE TABLE ...;\n",
    "permissions": "0640",
})
# "OK: Uploaded 19 bytes to /tmp/backup.sql"

# Check SSH connectivity
call_tool("ssh_check_connection", {"server_name": "web-server"})
# {"success": true, "output": "ping", "error": null, "exit_code": 0, "checkcommand": "echo ping"}

# Check with custom timeout
call_tool("ssh_check_connection", {"server_name": "web-server", "timeout": 5})
```

> **Note on sudo:** There is no `sudo_password` parameter. If sudo requires a password, it comes from the target's `password` field in the config. The `sudo` flag wraps with `sudo -S -p ''` (password from config) or `sudo -n` (passwordless).

### Error Responses

On failure a tool returns:

```json
{
  "error": true,
  "error_type": "AuthorizationError",
  "message": "Command rejected: target 'foo' not found",
  "retryable": false,
  "request_id": "abc-123"
}
```

Common `error_type` values: `AuthorizationError`, `PathValidationError`, `FileTransferError`, `SSHAuthenticationError`, `SSHTimeoutError`, `MCPSSHError`. The `retryable` flag is `true` for `SSHTimeoutError`. Rate-limit violations return HTTP 429 instead.

---

## Configuration

### Config File Location

The server reads `<config_dir>/ssh-mcp-config.json`. Set `config_dir` via `--config` CLI flag or `MCP_SSH_CONFIG_PATH` environment variable (default: `/config`). If the file doesn't exist, the server writes a bundled [`default-config.json`](default-config.json).

### Top-Level Structure

```jsonc
{
  "version": 1,
  "ssh_targets": { ... },
  "block_patterns": [ ... ],
  "allowed_commands": {
    "default": [ ... ],
    "api_keys": [ ... ],
    "networks": [ ... ]
  },
  "settings": { ... }
}
```

The config is validated against [`config.schema.json`](config.schema.json) (JSON Schema Draft 2020-12) at load time. Unknown keys cause a hard error.

### `ssh_targets`

An object keyed by server identifier. Each target requires `host`, `port`, `username`, and at least one of `private_key` or `password`.

```jsonc
"ssh_targets": {
  "web-server": {
    "host": "192.168.1.10",
    "port": 22,
    "username": "deploy",
    "private_key": "/app/ssh_key",
    "checkcommand": "echo ping"
  }
}
```

| Field | Required | Default | Description |
|---|---|---|---|
| `host` | Yes | — | Hostname or IP address |
| `port` | No | `22` | SSH port |
| `username` | Yes | — | SSH username |
| `private_key` | * | — | Path to SSH private key file on the server filesystem |
| `password` | * | — | SSH password (can also be set via `secrets.json` or env vars) |
| `checkcommand` | No | `"echo ping"` | Command executed by `ssh_check_connection` to verify connectivity |

\* At least one of `private_key` or `password` is required.

> `private_key` is a **path on the server's filesystem** (in Docker, mounted into the container), not an inline key.

### `block_patterns`

A list of regex patterns. Any command matching a pattern is **denied** regardless of other allow-list layers. Patterns are screened for catastrophic-backtracking constructs at load time (ReDoS protection) and compiled with timeout guards at runtime.

### `allowed_commands`

Three sub-objects control which commands each client may run:

- **`default`** — rules for all clients (unless a more specific layer decides first)
- **`api_keys`** — per-key rules, matched by `key_hash`
- **`networks`** — per-CIDR rules, matched by client source IP

Each rule has a `targets` list (server ids or `"*"` for all) and a `commands` list (base command names or `"*"` for any command).

```jsonc
"allowed_commands": {
  "default": [
    { "targets": ["*"], "commands": ["hostname", "uptime", "free", "df", "ps"] }
  ],
  "api_keys": [
    {
      "name": "ci-bot",
      "key_hash": "pbkdf2:sha256:100000$<salt>$<hash>",
      "rules": [
        { "targets": ["web-server"], "commands": ["systemctl", "journalctl"] }
      ]
    }
  ],
  "networks": [
    {
      "name": "home-lan",
      "range": "192.168.1.0/24",
      "rules": [
        { "targets": ["*"], "commands": ["*"] }
      ]
    }
  ]
}
```

### `settings`

| Setting | Default | Description |
|---|---|---|
| `max_output_length` | `50000` | Max bytes of command output returned to client (int or size string) |
| `command_timeout_max` | `120` | Hard cap on command timeout (seconds) |
| `retry_max_attempts` | `3` | Retry attempts for transient SSH failures |
| `retry_backoff_base_seconds` | `1.0` | Base exponential backoff (seconds) |
| `circuit_breaker_failure_threshold` | `5` | Failures before the circuit opens per target |
| `circuit_breaker_timeout_seconds` | `60.0` | Recovery timeout for an open circuit (seconds) |
| `log_level` | `"INFO"` | Log level: DEBUG, INFO, WARNING, ERROR |
| `max_log_output` | `4096` | Max chars of output stored in log entries |
| `compress_rotated` | `true` | Gzip rotated log files |
| `pool_max_connections_per_target` | `5` | Max pooled SSH connections per target |
| `pool_idle_timeout_seconds` | `300.0` | Idle connection timeout (seconds) |
| `pool_cleanup_interval_seconds` | `60.0` | Pool cleanup interval (seconds) |
| `max_concurrent_ssh_connections` | `20` | Global cap across all targets; excess returns HTTP 503 |
| `watcher_debounce_seconds` | `2.0` | Min gap between config reloads; `0` disables |
| `trusted_proxies` | `[]` | Trusted reverse-proxy IPs (IPv4/IPv6) |

#### SFTP Settings (`settings.sftp`)

| Setting | Default | Description |
|---|---|---|
| `sftp.sandbox_root` | `"/"` | Root directory for SFTP path validation |
| `sftp.max_path_length` | `4096` | Maximum allowed SFTP path length (bytes); `0` disables |

### Secrets

SSH target passwords and API-key hashes can be separated from the main config into `<config_dir>/secrets.json` or `MCP_SSH_SECRET_*` environment variables. Precedence:

```
environment variables  >  secrets.json  >  ssh-mcp-config.json
```

| Secret source | Effect |
|---|---|
| `secrets.json` | Per-target `password` and per-key `key_hash` overrides (matched by name) |
| `MCP_SSH_SECRET_PASSWORD_<TARGET_ID>` | Override `ssh_targets[<TARGET_ID>].password` |
| `MCP_SSH_SECRET_API_KEY_<KEY_NAME>` | Override `key_hash` for `api_keys` entry `<KEY_NAME>` |

`<TARGET_ID>` and `<KEY_NAME>` are upper-cased with `-` → `_`. API-key values must be **hash strings**, not raw keys.

### Environment Variables and CLI Flags

| Environment variable | CLI flag | Default | Legacy fallback |
|---|---|---|---|
| `MCP_SSH_CONFIG_PATH` | `--config` | `/config` | `CONFIG_DIR` |
| `MCP_SSH_SSH_KEY` | `--ssh-key` | `ssh_key` | `SSH_KEY_PATH` |
| `MCP_SSH_LOG_DIR` | `--log-dir` | `/logs` | `LOG_DIR` |
| `MAX_OUTPUT_LENGTH` | `--max-output` | `50000` | — |
| `CONFIG_API_ENABLED` | — | `false` | — |
| `CONFIG_API_TOKEN` | — | *(required when API enabled)* | — |
| — | `--fix-permissions` | `False` | — |
| — | `--print-default-config` | — | — |

CLI flags take precedence over environment variables. Any `settings` key can be overridden at runtime with `MCP_SSH_SETTING_<KEY>` (upper-cased, `-` → `_`).

### Hot Reload

The server polls the config file for changes (15 s interval, 2 s debounce). When a change is detected, it reloads, validates, and atomically swaps in the new configuration. Config-change callbacks (authorization rules rebuild, connection pool refresh) run after the swap succeeds. Watchdog-based file monitoring is used when available.

---

## Observability

### Health Check

`GET /health` returns `{"status": "ok"}` plus connection pool stats. The container's `HEALTHCHECK` uses this endpoint.

### Prometheus Metrics

`GET /metrics` exposes metrics on a dedicated registry, all prefixed `mcpssh_`:

| Metric | Type | Labels |
|---|---|---|
| `mcpssh_requests_total` | Counter | `tool`, `status` (success/error/denied) |
| `mcpssh_ssh_connections_total` | Counter | `target` |
| `mcpssh_ssh_connection_duration_seconds` | Histogram | `target` |
| `mcpssh_auth_denials_total` | Counter | `reason` |
| `mcpssh_command_duration_seconds` | Histogram | `target` |
| `mcpssh_pool_active_connections` | Gauge | `target` |
| `mcpssh_pool_idle_connections` | Gauge | `target` |
| `mcpssh_pool_created_total` | Counter | `target` |

### Structured Logging

The mcp-ssh server supports pluggable log targets configured via `settings.logging.log_targets` in the config file. Each target is an independent driver that receives all log entries.

#### Default Behavior

By default, log entries are written to **stdout** in human-readable text format. This is suitable for Docker environments where container logs are captured by the runtime.

#### Log Target Types

| Target | Config value | Format | Description |
|--------|-------------|--------|-------------|
| Stdout | `"stdout"` | Text | Writes to stdout. Default target. |
| JSON File | `"jsonfile"` | JSONL | Writes one JSON object per line to a file. |
| Text File | `"file"` | Text | Writes human-readable text to a file. |

#### Configuration

```json
{
  "settings": {
    "log_level": "INFO",
    "logging": {
      "log_targets": [
        { "target": "stdout" },
        { "target": "jsonfile", "filepath": "logs/ssh-mcp.log" }
      ],
      "max_log_output": 4096,
      "compress_rotated": true
    }
  }
}
```

#### Log Level

- **Config file:** Set `settings.log_level` to control the default level.
- **Environment variable:** Set `MCP_SSH_LOG_LEVEL` to override the config-file default (e.g., `MCP_SSH_LOG_LEVEL=DEBUG`).
- **Per-target:** Each log target can have its own `log_level` that overrides the default.

#### Legacy Configuration

If `settings.logging` is absent, the server falls back to a single JSONL file target in the log directory (`/logs` by default). This maintains backward compatibility with existing configurations.

#### Text Format

Stdout and text-file targets use the format:

```
2025-01-15 10:30:00 INFO ssh_execute_command: Command executed on server1
```

#### JSON Format

JSON-file targets write one JSON object per line:

```json
{"timestamp": "2025-01-15T10:30:00+00:00", "event": "ssh_execute_command", "level": "INFO", "message": "Command executed on server1", "request_id": "abc-123", "log_level": "INFO", "log_format_version": 1}
```

#### File Rotation

File-based targets rotate when they exceed `max_file_size_mb` (default: 10 MiB), keeping `backup_count` backups (default: 5). Rotated files are gzip-compressed when `compress_rotated` is `true`.

#### Configuration Change Events

| Event | Meaning |
|---|---|
| `config.load` | Initial config loaded at startup |
| `config.reload` | Config re-read from disk (with `success`, `changed_keys`, `targets_added`, `targets_removed`) |
| `config.migrated` | Schema migration applied (`from_version`, `to_version`) |
| `config.default_created` | Bundled default config copied |
| `config.fallback` | Fell back to in-memory defaults |
| `config.callback_error` | Config-change callback raised exception |

---

## Configuration API & Web Dashboard

The unified container includes an optional **Configuration API and Web Dashboard** — a full management plane for your SSH policy, targets, command rules, and backups. No config-file editing required. This feature is disabled by default.

### What You Get

- **Web Dashboard** — a responsive single-page application with 5 pages: SSH Targets, Block Patterns, Command Rules, Settings, and Backups. Login with your API token and manage everything from the browser.
- **REST API** — full CRUD for every config section, plus config validation, API key hashing, backup management, and inline SSH connectivity testing.
- **API Key Hashing Utility** — hash plaintext API keys into PBKDF2 strings ready for config. No more guessing the hash format.
- **Backup & Restore** — automatic config backups on every write; list, restore, or delete backups from the dashboard or API.
- **Atomic, Thread-Safe Writes** — all config writes are validated, serialized with a threading lock, and atomically written to disk.
- **Swagger UI & ReDoc** — auto-generated interactive API documentation at `/api/docs` and `/api/redoc`.

### Enabling the Configuration API

Set these environment variables in your `compose.yaml` or `.env` file:

| Variable | Default | Description |
|---|---|---|
| `CONFIG_API_ENABLED` | `false` | Set to `true` to enable the Configuration API |
| `CONFIG_API_TOKEN` | *(required when enabled)* | Bearer token for authenticating API requests |

```yaml
services:
  mcp-ssh:
    environment:
      CONFIG_API_ENABLED: "true"
      CONFIG_API_TOKEN: "your-secret-token-here"
```

### API Endpoints

All endpoints are mounted at `/api` on the same Starlette ASGI application as the MCP server.

#### Health & Utilities

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check for the config API (no auth required) |
| `POST` | `/api/hash-key` | Hash a plaintext API key into a PBKDF2-HMAC-SHA256 string |
| `GET` | `/api/config/schema` | Return the config JSON Schema (no auth required) |
| `POST` | `/api/config/validate` | Validate a config dict without writing it to disk |

#### Configuration

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/config` | Get the full configuration (redacts secrets) |
| `PUT` | `/api/config` | Replace the full configuration |
| `GET` | `/api/config/{section}` | Get a single config section (`settings`, `ssh_targets`, `allowed_commands`, `block_patterns`) |
| `PUT` | `/api/config/{section}` | Replace a single config section |

#### SSH Targets

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/config/ssh_targets/{name}` | Get a specific SSH target (secrets stripped) |
| `PUT` | `/api/config/ssh_targets/{name}` | Create or replace an SSH target |
| `DELETE` | `/api/config/ssh_targets/{name}` | Delete an SSH target |
| `POST` | `/api/config/ssh_targets/{name}/check` | Test SSH connectivity via the target's `checkcommand` |

#### Command Rules

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/config/allowed_commands` | List allowed command rules (via `GET /api/config/{section}`) |
| `PUT` | `/api/config/allowed_commands` | Replace allowed command rules (via `PUT /api/config/{section}`) |

#### Block Patterns

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/config/block_patterns` | List block patterns (via `GET /api/config/{section}`) |
| `PUT` | `/api/config/block_patterns` | Replace all block patterns |
| `POST` | `/api/config/block_patterns` | Append a block pattern |
| `PUT` | `/api/config/block_patterns/{index}` | Replace a single block pattern by index |
| `DELETE` | `/api/config/block_patterns/{index}` | Remove a single block pattern by index |

#### Backups

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/backups` | List config backups (newest first) |
| `POST` | `/api/backups/{name}/restore` | Restore configuration from a backup |
| `DELETE` | `/api/backups/{name}` | Delete a backup file |

### Authentication

All API requests (except `/api/health` and `/api/config/schema`) require a `Bearer` token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer your-secret-token-here" http://localhost:9080/api/config
```

### Web Dashboard

When enabled, a **responsive single-page application** is available at `http://localhost:9080/ui/` — a full management UI built with Tailwind CSS. No page reloads, toast notifications for every operation, and modal dialogs for editing.

| Page | Capabilities |
|---|---|
| **SSH Targets** | View, add, edit, delete targets; inline connectivity testing via `checkcommand`; table view with host/port/username |
| **Block Patterns** | Add, edit (by index), delete individual patterns; view the full pattern list |
| **Command Rules** | Edit default, API-key, and network rules; full rules editor with target and command lists |
| **Settings** | Edit all server settings: SFTP sandbox, rate limiting, logging, connection pooling, circuit breaker, and more |
| **Backups** | List, restore, and delete configuration backups; timestamp and size for each backup |

Additional features:
- **Token-based login** with session management (stored in `sessionStorage`)
- **Config validation** — changes are validated before writing
- **API key hashing** — hash plaintext keys directly from the dashboard
- **Responsive design** — works on desktop and mobile
- **Toast notifications** — success/error feedback for every operation

### Swagger / ReDoc

Interactive API documentation is auto-generated by FastAPI:
- Swagger UI: `http://localhost:9080/api/docs`
- ReDoc: `http://localhost:9080/api/redoc`

---

## Deployment

### Docker Compose

The [`compose.yaml`](compose.yaml) defines a single `mcp-ssh` service that hosts both the MCP server and, optionally, the Configuration API & Web Dashboard. The config API is enabled via the `CONFIG_API_ENABLED` environment variable (default: `false`).

#### `mcp-ssh` — MCP SSH Gateway + Config API

| Host path | Container path | Mode |
|---|---|---|
| `./config` | `/config` | rw |
| `./logs` | `/logs` | rw |
| `./ssh_key` | `/app/ssh_key` | ro |
| `./ssh_key.pub` | `/app/ssh_key.pub` | ro |

Exposed on host port `9080` (maps to container port `8080`). The runtime image is `python:3.13-alpine` with a hash-pinned digest. A non-root `mcpssh` user runs the process. A CycloneDX SBOM is generated at build time in the `sbom` stage.

#### Configuration API & Web Dashboard (optional)

Enable the config API by setting `CONFIG_API_ENABLED=true` in your `.env` file or environment:

```bash
# Generate an auth token
openssl rand -hex 32
```

```env
CONFIG_API_ENABLED=true
CONFIG_API_TOKEN=<your-token>
```

When enabled, the config API is mounted at `/api` on the same HTTP server as the MCP gateway. It provides:

- **REST API** at `http://localhost:9080/api/...` — full CRUD for SSH targets, block patterns, command rules, backups, and settings
- **Web Dashboard (GUI)** at `http://localhost:9080/ui/` — a single-page application for visual policy management (SSH targets, block patterns, command rules, settings, backups)
- **API docs** at `http://localhost:9080/api/docs` (Swagger UI) and `http://localhost:9080/api/redoc` (ReDoc)

### Makefile

| Command | Description |
|---|---|
| `make build` | Build the Docker image (`ghcr.io/gelse/ssh-mcp:latest`) |
| `make up` | `docker compose up -d` |
| `make down` | `docker compose down` |
| `make test` | Run unit tests |
| `make config-test` | Run config-api unit tests |
| `make integrationtest` | Build test image, run integration tests |
| `make clean-test` | Remove test artifacts and containers |

### Pull from GHCR

The Docker image is automatically built and published to GitHub Container Registry:

```bash
docker pull ghcr.io/gelse/ssh-mcp:latest
```

---

## Limitations and Threat Model

### What ssh-mcp Is Not

- **Not a shell.** You cannot get an interactive terminal session. All execution is one-shot command calls.
- **Not a file manager.** SFTP is limited to single-file upload/download with path validation and sandbox enforcement. No directory listing, no recursive operations.
- **Not a network firewall.** Rate limiting is per-IP with fixed defaults. It protects against runaway clients, not determined attackers.

### Threat Model

| Threat | Mitigation |
|---|---|
| Command injection via chaining (`cmd1 && cmd2`) | Command segmentation — each segment runs the full authorization chain |
| Shell redirection to sensitive paths (`> /etc/passwd`) | Redirection-target guard denies redirects into `/dev/`, `/proc/`, `/sys/` |
| Path traversal in SFTP | 8-layer path validation: null-byte check, control-char strip, dot-segment normalization, symlink resolution, sandbox-root enforcement |
| ReDoS via `block_patterns` | Static screening at load time + runtime timeout guards |
| API key brute force | PBKDF2-HMAC-SHA256 with constant-time verify; rate limiting per IP |
| Log injection | Newline sanitization on all user-controlled fields before logging |
| Secrets in config | `secrets.json` separation, `MCP_SSH_SECRET_*` env vars, `0600` file permissions |

### Not In Scope

- TLS termination (handled by your reverse proxy)
- User authentication beyond API keys (no OAuth, no mTLS at the application layer)
- SSH session multiplexing (no tmux/screen passthrough)
- Audit log tamper protection (logs are local files; use your own log shipping for immutability)

---

## Development

### Project Structure

- [`server.py`](server.py) — FastMCP app factory + CLI entry point
- [`lib/`](lib/) — 30 single-responsibility modules (auth, config, SSH client, file transfer, logging, etc.)
- [`config-api/`](config-api/) — Configuration API + Web Dashboard (FastAPI, mounted at `/api` when `CONFIG_API_ENABLED=true`)
- [`tests/`](tests/) — 36 unit-test files + integration tests with real Docker containers

### Tech Stack

Python 3.13, [FastMCP](https://gofastmcp.com/) 3.4.x, [paramiko](https://www.paramiko.org/) 5.0, Starlette 1.4, [FastAPI](https://fastapi.tiangolo.com/) 0.115+, [Pydantic](https://docs.pydantic.dev/) 2.10+, [httpx](https://www.python-httpx.org/) 0.28+, [uvicorn](https://www.uvicorn.org/) 0.34+

### Running Tests

```bash
# Unit tests (fast inner loop)
source .venv/bin/activate
python -m pytest tests/test_<module>.py -x

# Full unit test suite
make test

# Integration tests (requires Docker)
make integrationtest
```

### Adding a New Tool

The [worked example in AGENTS.md](AGENTS.md#worked-example--adding-a-read-only-tool) walks through adding a new `@mcp.tool()` handler end-to-end: constants, types, re-exports, handler, tests, commit.

### No Lint/Type-Check Tooling

The project has no `ruff`, `mypy`, `pyright`, or `flake8` configuration. Formatting follows `.editorconfig` defaults (4 spaces for Python, 88-char lines).

---

## Roadmap

- [x] Configuration GUI for visual policy management

---

## License

MIT License — see [`LICENSE`](LICENSE) for details.
