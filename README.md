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
- [Deployment](#deployment)
- [Limitations and Threat Model](#limitations-and-threat-model)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

---

## Architecture

### Local stdio MCP (common pattern)

```
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
curl http://localhost:8080/health
# {"status": "ok", "connection_pool": {...}}
```

### 5. Connect an MCP client

Any MCP client supporting Streamable HTTP can connect. Point it at `http://localhost:8080/mcp` with an API key header. See [MCP Client Configuration](#mcp-client-configuration) for details.

### 6. List servers and run a command

```bash
curl -X POST http://localhost:8080/mcp \
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

curl -X POST http://localhost:8080/mcp \
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
      "url": "http://localhost:8080/mcp",
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
curl -X POST http://localhost:8080/mcp \
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
    "private_key": "/app/ssh_key"
  }
}
```

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

JSONL logs are written to `LOG_DIR` (default `/logs`). Each entry includes `timestamp`, `log_level`, `event`, `request_id` (correlation ID), `source_ip`, `api_key_name`, `target_name`, `command`, `allowed`, `reason`, `matched_via`, `execution_time_ms`, `exit_code`, and optionally `output` (truncated to `max_log_output`).

Files rotate at 10 MB keeping 5 backups; rotated files are gzipped when `compress_rotated` is enabled. User-controlled fields (`command`, `target_name`, remote paths) are newline-sanitized before logging.

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

## Deployment

### Docker Compose

The [`compose.yaml`](compose.yaml) mounts:

| Host path | Container path | Mode |
|---|---|---|
| `./config` | `/config` | rw |
| `./logs` | `/logs` | rw |
| `./ssh_key` | `/app/ssh_key` | ro |
| `./ssh_key.pub` | `/app/ssh_key.pub` | ro |

The runtime image is `python:3.13-alpine` with a hash-pinned digest. A non-root `mcpssh` user runs the process. A CycloneDX SBOM is generated at build time in the `sbom` stage.

### Traefik Integration

The compose file ships with Traefik labels that route `ssh-mcp.example.com` over HTTPS to the container. The server reads no `TRAEFIK_*` environment variables — labels are compose-level configuration only. A headers middleware sets `X-Forwarded-For` so rate limiting sees the real client IP.

### Makefile

| Command | Description |
|---|---|
| `make build` | Build the Docker image (`mcp-ssh:local`) |
| `make up` | `docker compose up -d --build` |
| `make down` | `docker compose down` |
| `make test` | Run unit tests |
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
- [`lib/`](lib/) — 24 single-responsibility modules (auth, config, SSH client, file transfer, etc.)
- [`tests/`](tests/) — 29 unit-test files + integration tests with real Docker containers

### Tech Stack

Python 3.13, [FastMCP](https://gofastmcp.com/) 3.4.x, [paramiko](https://www.paramiko.org/) 5.0, Starlette 1.4

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

- [ ] Configuration GUI for visual policy management

---

## License

MIT License — see [`LICENSE`](LICENSE) for details.
