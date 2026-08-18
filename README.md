# mcp-ssh

**mcp-ssh** is a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that exposes SSH command execution and SFTP file transfer as MCP tools. It is designed to run as a small Docker service (behind a TLS reverse proxy such as Traefik) and give MCP clients — like Claude Desktop or custom agents — controlled, auditable access to your servers.

The server speaks **streamable HTTP** on port `8080` at the `/mcp` path and registers exactly five tools: `ssh_list_servers`, `ssh_list_allowed_commands`, `ssh_execute_command`, `ssh_download_file`, and `ssh_upload_file`.

> **Truth-first documentation:** every statement in this README reflects the current implementation. Planned work is explicitly marked as *planned* and is **not** implemented yet.

---

## Table of Contents

- [1. Summary](#1-summary)
- [2. Configuration](#2-configuration)
- [3. Deployment](#3-deployment)
- [4. User Guide](#4-user-guide)
- [Additional Resources](#additional-resources)

---

## 1. Summary

### What it does

| Capability | Description |
|---|---|
| **MCP tools** | 5 tools: list servers, list allowed commands, execute command, download file, upload file |
| **Transport** | Streamable HTTP, listens on `0.0.0.0:8080`, MCP path `/mcp` |
| **Command authorization** | Layered allow-list chain: `block_patterns` → dangerous patterns → redirection-target guard → redirector stripping → command segmentation → `default` rules → API key rules → network rules → deny. Redirection operators (`2>&1`, `>`, `>>`, `&>`, …) are stripped before segmentation so they never cause phantom-segment denials, while block/dangerous patterns still run against the raw command first |
| **API key authentication** | Keys are stored as **hashes** in the config file (PBKDF2-HMAC-SHA256 with per-key random salt; legacy `sha256:` hashes supported). Verified with constant-time comparison. Keys are sent via `X-API-Key` or `Authorization: Bearer` headers |
| **SSH connection pooling** | Reuses connections per target (configurable max connections, idle timeout, cleanup interval) |
| **Rate limiting** | Sliding-window limiter per client IP (defaults: 60 requests / 60 s window; `/health` is exempt). Returns HTTP 429 with `Retry-After` |
| **Circuit breaker** | Per-target failure threshold + recovery timeout so a failing host does not stall the server |
| **Retry with backoff** | Automatic retries for transient SSH failures (configurable attempts + base backoff) |
| **Sudo support** | `sudo -S -p ''` when the target config provides a password, or `sudo -n` for passwordless sudo |
| **SFTP security** | 7-layer path validation; uploads are only allowed under `/tmp/` or `/home/`; 10 MiB max file size |
| **Structured logging** | JSONL logs with rotation (10 MB, 5 backups, optional gzip), output truncation, per-request correlation IDs |
| **Input sanitization** | `command`, `server_name`, and log fields are sanitized before authorization: null bytes and control chars stripped (except `\t`/`\n`/`\r`), NFKC-normalized, and server names validated against `[a-zA-Z0-9._-]{1,128}` |
| **Config hot-reload** | `ssh-mcp-config.json` is re-read on change (15 s polling, 2 s debounce) — no restart required. Authorization rules are rebuilt into an immutable `RulesSnapshot` and swapped atomically, so readers never observe a partially-updated rule set |
| **Observability** | `GET /health` and `GET /metrics` (Prometheus) endpoints |
| **Docker hardening** | Non-root `mcpssh` user, hash-pinned base image, CycloneDX SBOM build stage |

### Planned improvements (not yet implemented)

The following items are tracked in the project plans (`plans/11a-separate-secrets-env-overrides-migration.md`) but are **not** part of the current code:

- Duplicate SSH-target detection

---

## 2. Configuration

> **Target audience:** operators who set up the server.

### 2.1 Config file location

The server reads its configuration from `<config_dir>/ssh-mcp-config.json`, where `config_dir` is the `--config` CLI flag or the `CONFIG_DIR` environment variable (default `/config`). See [§3 Deployment](#3-deployment) for how this maps to Docker.

If the config file does not exist and the directory is writable, the server writes a bundled `default-config.json` so it can start. If the directory is not writable, it falls back to the bundled defaults in memory.

To see the exact config the server would generate, run the server with the `--print-default-config` flag. It prints the generated default config as pretty-printed JSON to stdout and exits without starting the server or touching the filesystem:

```bash
./server.py --print-default-config
```

The config file format is also described by a bundled JSON Schema, [`config.schema.json`](config.schema.json) (JSON Schema Draft 2020-12). It ships with the repository, is copied into the container image, and `default-config.json` points at it via its top-level `$schema` key. Editors and CI can use the schema to validate `ssh-mcp-config.json` structure.

Sensitive values (SSH target passwords and API-key hashes) may instead live in a separate `<config_dir>/secrets.json` file or in environment variables — see [§2.8 Secrets](#28-secrets).

### 2.2 Top-level structure

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

The top-level `version` key declares the config schema version. On load the
server migrates the config to the latest supported version automatically:

- A missing `version` is treated as `1` (the original format predated version tracking) — no migration is performed.
- If the config is older than the latest version, the server applies the registered migrations and **rewrites `ssh-mcp-config.json` in place**, first writing an atomic pre-migration backup to `<config_file>.bak` (with mode `0600`). If the rewrite fails (e.g. a read-only filesystem), the migrated config is used in memory only and a `config.migrated` failure event is logged.
- A config whose `version` is **newer** than this release understands is rejected at load time (a hard error), since the server cannot downgrade it.

### 2.3 `ssh_targets`

An object keyed by server identifier. Each target requires a `host`, `port`, and `username`, plus **at least one** of `private_key` or `password`.

```jsonc
"ssh_targets": {
  "web-server": {
    "host": "192.168.1.10",
    "port": 22,
    "username": "deploy",
    "private_key": "/app/ssh_key"
  },
  "db-server": {
    "host": "db.internal",
    "port": 22,
    "username": "root"
  }
}
```

> **Note:** `private_key` is a *path on the server's filesystem* to the private key file (in Docker, mounted into the container), not an inline key.

The `password` field may still be present inline (backward-compatible fallback), but it should prefer `secrets.json` or a `MCP_SSH_SECRET_PASSWORD_*` environment variable — see [§2.8 Secrets](#28-secrets).

### 2.4 `block_patterns`

A list of regex patterns. Any command matching a pattern is **denied**, regardless of other allow-list layers. The bundled defaults include:

```jsonc
"block_patterns": [
  "\\bsudo\\b",
  "\\brm\\s+-rf\\b",
  "\\bdd\\s+if=",
  "\\b>:.*/(dev|proc|sys)/",
  "\\bmkfs\\.",
  "\\bwipefs\\b",
  "\\bshutdown\\b",
  "\\breboot\\b",
  "\\bpoweroff\\b",
  "\\binit\\s+[06]",
  "\\bhalt\\b"
]
```

### 2.5 `allowed_commands`

Three sub-objects control which commands each client may run.

#### `default`

Rules that apply to **all** clients (unless a more specific layer grants/denies first). Each rule is an object with a `targets` list (server ids, or `"*"` for all) and a `commands` list (base command names, or `"*"` for any command).

```jsonc
"default": [
  {
    "targets": ["*"],
    "commands": ["hostname", "uptime", "free", "df", "du", "systemctl", "journalctl", "ps", "ls", "cat", "head", "tail", "grep"]
  },
  {
    "targets": ["db-server"],
    "commands": ["psql"]
  }
]
```

#### `api_keys`

A **list** of objects, each with `name` (a label, e.g. the client name), `key_hash` (the hashed API key), and `rules` (same shape as `default` rules). Clients authenticate by sending their raw key; the server hashes it and matches it against `key_hash`.

```jsonc
"api_keys": [
  {
    "name": "ci-bot",
    "key_hash": "pbkdf2:sha256:100000$<salt-hex>$<hash-hex>",
    "rules": [
      { "targets": ["web-server"], "commands": ["systemctl", "journalctl"] }
    ]
  }
]
```

The `key_hash` (and only the `key_hash`) may instead live in `secrets.json` or a `MCP_SSH_SECRET_API_KEY_*` environment variable; `name` and `rules` stay in the main config — see [§2.8 Secrets](#28-secrets).

**How to generate `key_hash`:** the server hashes keys with PBKDF2-HMAC-SHA256 (100,000 iterations, random 32-byte salt). Generate the hash with the same parameters the server uses:

```bash
python3 - <<'EOF'
import hashlib, os
key = "my-secret-key"                       # the raw key your client will send
salt = os.urandom(32)
dk = hashlib.pbkdf2_hmac("sha256", key.encode(), salt, 100000)
print(f"pbkdf2:sha256:100000${salt.hex()}${dk.hex()}")
EOF
```

> **Important:** `key_hash` is the **only** thing stored in the config — never store raw API keys in `ssh-mcp-config.json`. Legacy `sha256:<64-hex>` hashes (unsalted) are also accepted for compatibility.

#### `networks`

A **list** of objects, each with `name`, `range` (CIDR), and `rules` (same shape as above). A client whose source IP falls inside the range gets the corresponding rules.

```jsonc
"networks": [
  {
    "name": "home-lan",
    "range": "192.168.1.0/24",
    "rules": [
      { "targets": ["*"], "commands": ["*"] }
    ]
  }
]
```

### 2.6 `settings`

All settings are **flat keys** — there is no nesting (and no `rate_limit` key; see below). Unknown keys cause the config to be rejected at load time.

| Setting | Default | Description |
|---|---|---|
| `max_output_length` | `50000` | Max bytes of command output returned to the client. Accepts an integer (bytes) or a case-insensitive size string with a `b`/`kb`/`mb`/`gb` suffix (e.g. `"1KB"`, `"50kb"`, `"10mb"`); a bare number is treated as bytes |
| `command_timeout_max` | `120` | Hard cap on command timeout (seconds) |
| `retry_max_attempts` | `3` | Retry attempts for transient SSH failures |
| `retry_backoff_base_seconds` | `1.0` | Base exponential backoff (seconds) |
| `circuit_breaker_failure_threshold` | `5` | Failures before the circuit opens per target |
| `circuit_breaker_timeout_seconds` | `60.0` | Recovery timeout for an open circuit (seconds) |
| `log_level` | `"INFO"` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `max_log_output` | `4096` | Max chars of output stored in log entries |
| `compress_rotated` | `true` | Gzip rotated log files |
| `pool_max_connections_per_target` | `5` | Max pooled SSH connections per target |
| `pool_idle_timeout_seconds` | `300.0` | Idle connection timeout (seconds) |
| `pool_cleanup_interval_seconds` | `60.0` | Pool cleanup interval (seconds) |
| `max_concurrent_ssh_connections` | `20` | Global maximum of concurrently checked-out SSH connections across all targets; excess acquisitions are rejected with an HTTP 503 `ServiceUnavailableError` rather than queued |
| `watcher_debounce_seconds` | `2.0` | Minimum gap (seconds) between config reloads triggered by file changes; `0` disables debouncing |

> **Rate limiting note:** the sliding-window rate limiter currently uses **fixed defaults** (60 requests per minute per client IP, 60-second window, `/health` exempt). A `settings.rate_limit` key is **rejected** by config validation in this version — it is a planned configuration surface, not a working one.

### 2.7 Environment variables and CLI flags

Each of these environment variables maps 1:1 to a CLI flag; CLI flags take
precedence over environment variables:

| Environment variable | CLI flag | Default | Legacy fallback |
|---|---|---|---|
| `MCP_SSH_CONFIG_PATH` | `--config` | `/config` | `CONFIG_DIR` |
| `MCP_SSH_SSH_KEY` | `--ssh-key` | `ssh_key` | `SSH_KEY_PATH` |
| `MCP_SSH_LOG_DIR` | `--log-dir` | `/logs` | `LOG_DIR` |
| `MAX_OUTPUT_LENGTH` | `--max-output` | `50000` | — |
| — | `--fix-permissions` | `False` (disabled) | — |
| — | `--print-default-config` | `False` (disabled) | — |

The legacy variable names (`CONFIG_DIR`, `SSH_KEY_PATH`, and `LOG_DIR`)
remain supported as fallbacks: the `MCP_SSH_*` name wins when both are set.

> **Not read by the server:** `API_KEYS`, `SSH_TARGETS_FILE`, `SSL_CERT_PATH`, `SSL_KEY_PATH`, `TRAEFIK_HOST`, `TRAEFIK_PORT`, `TRAEFIK_ENTRYPOINTS`, `CONFIG_PATH`. Traefik settings are compose-level labels, not server config. (In addition to the flags above, the server reads `MCP_SSH_SECRET_*` variables — see §2.8 — and `MCP_SSH_SETTING_*` variables — see §2.7.1.)

#### 2.7.1 Setting overrides

Any key in the `settings` table (see §2.6) can be overridden at runtime with
`MCP_SSH_SETTING_<KEY>`, where `<KEY>` is the setting name upper-cased with
`-` replaced by `_`. Values are coerced to the declared type (int, float,
bool, or str); a variable whose name is unknown or whose value cannot be
coerced is ignored with a warning. Precedence is:

```
env vars  >  secrets.json  >  ssh-mcp-config.json  >  defaults
```

Examples:

| Env var | Equivalent setting |
|---|---|
| `MCP_SSH_SETTING_MAX_OUTPUT_LENGTH=100` | `settings.max_output_length = 100` (size strings like `10mb` are also accepted and normalised to bytes) |
| `MCP_SSH_SETTING_COMPRESS_ROTATED=true` | `settings.compress_rotated = true` |
| `MCP_SSH_SETTING_LOG_LEVEL=DEBUG` | `settings.log_level = "DEBUG"` |
| `MCP_SSH_SETTING_WATCHER_DEBOUNCE_SECONDS=5` | `settings.watcher_debounce_seconds = 5.0` |

### 2.8 Secrets

SSH target passwords and API-key hashes can be separated from `ssh-mcp-config.json` into a dedicated `secrets.json` file and/or `MCP_SSH_SECRET_*` environment variables. The server merges them during load with this precedence:

```
environment variables  >  secrets.json  >  ssh-mcp-config.json
```

#### `secrets.json`

Placed at `<config_dir>/secrets.json`:

```jsonc
{
  "version": 1,
  "ssh_targets": {
    "db-server": { "password": "CHANGE_ME" }
  },
  "api_keys": [
    { "name": "ci-bot", "key_hash": "pbkdf2:sha256:100000$<salt-hex>$<hash-hex>" }
  ]
}
```

- `ssh_targets.<id>.password` overrides the target's password in the main config.
- `api_keys` entries are matched **by `name`** to the `allowed_commands.api_keys` list in the main config; only the `key_hash` is patched. `name` and `rules` stay in the main config, and a secrets entry whose name does not exist is ignored (it never creates new auth policy).
- The file must not be world-readable. The server warns (`secrets.permissions_insecure`) when it is more permissive than `0o600`; the `--fix-permissions` CLI flag auto-corrects it (along with `ssh-mcp-config.json`) to `0o600` on startup, emitting `secrets.permissions_fixed` / `config.permissions_fixed` events.
- A missing `secrets.json` is valid — the server simply falls back to the main config.

#### `MCP_SSH_SECRET_*` environment variables

| Env var | Effect |
|---|---|
| `MCP_SSH_SECRET_PASSWORD_<TARGET_ID>` | Override `ssh_targets[<TARGET_ID>].password` |
| `MCP_SSH_SECRET_API_KEY_<KEY_NAME>` | Override the `key_hash` of the `api_keys` entry named `<KEY_NAME>` |

`<TARGET_ID>` and `<KEY_NAME>` are upper-cased with `-` → `_` (e.g. `db-server` → `DB_SERVER`, `ci-bot` → `CI_BOT`). An empty value is treated as unset and falls through to the next source. Unknown `MCP_SSH_SECRET_*` variables are ignored but may emit a `secrets.unknown_env_var` log event. API-key values must be **hash strings**, not raw keys.

---

## 3. Deployment

> **Target audience:** operators deploying the server, typically with Docker.

### 3.1 Prerequisites

- Docker with Docker Compose (the provided [`compose.yaml`](compose.yaml) targets the `traefik` network)
- An SSH key pair (or per-target passwords) for the servers you want to reach
- A directory layout like this (used by the compose file):

```
.
├── compose.yaml
├── config/
│   └── ssh-mcp-config.json
├── logs/
├── ssh_key            # private key (mounted read-only)
└── ssh_key.pub
```

### 3.2 Build and run

```bash
# 1. Prepare the config directory
mkdir -p config logs

# 2. Create the SSH key (or reuse an existing one)
ssh-keygen -t ed25519 -f ssh_key -N ""

# 3. Create config/ssh-mcp-config.json (see §2 Configuration)

# 4. Start the server
docker compose up -d --build
```

The `compose.yaml` mounts:

| Host path | Container path | Mode |
|---|---|---|
| `./config` | `/config` | rw |
| `./logs` | `/logs` | rw |
| `./ssh_key` | `/app/ssh_key` | ro |
| `./ssh_key.pub` | `/app/ssh_key.pub` | ro |

and sets `CONFIG_DIR=/config`, `LOG_DIR=/logs`.

### 3.3 Traefik integration

The compose file ships with Traefik labels that route the external host `ssh-mcp.example.com` (change it to your domain) over HTTPS to the container:

- Router rule `Host(`ssh-mcp.example.com`)`, entrypoint `https`, TLS enabled
- Load balancer on container port `8080`
- A headers middleware sets `X-Forwarded-For` so rate limiting sees the real client IP
- The container joins the external `traefik` Docker network

These labels are **compose-level configuration** — the server itself does not read any `TRAEFIK_*` environment variables.

### 3.4 Health check

The container's `HEALTHCHECK` runs `wget --spider http://localhost:8080/health`. The `GET /health` endpoint returns `{"status": "ok"}` (plus a `connection_pool` object when pool stats are available).

### 3.5 Makefile

| Command | Description |
|---|---|
| `make build` | Build the Docker image (`mcp-ssh:local`) |
| `make up` | `docker compose up -d --build` |
| `make down` | `docker compose down` |
| `make test` | Run unit tests only |
| `make integrationtest` | Install dev/test deps, build the test image, and run integration tests |
| `make clean-test` | Remove test artifacts and containers |

---

## 4. User Guide

> **Target audience:** MCP clients (agents, Claude Desktop, custom code) that call the tools.

### 4.1 Server endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/mcp` | POST | MCP streamable-HTTP endpoint (all tool calls) |
| `/health` | GET | Liveness check → `{"status": "ok"}` |
| `/metrics` | GET | Prometheus metrics |

### 4.2 Authentication

Send your API key on every request via either:

- `X-API-Key: <your-raw-key>`, or
- `Authorization: Bearer <your-raw-key>`

The key is matched against the hashed `api_keys` entries in `ssh-mcp-config.json`. Unauthenticated requests fall through to the `default` rules; if no layer allows the command, it is denied.

### 4.3 Tools

All tool calls are JSON-RPC `tools/call` requests to `/mcp`. All tools return a **string** (JSON or plain text).

#### `ssh_list_servers()`

Lists configured SSH targets **without secrets**.

- **Parameters:** none
- **Returns:** JSON object `{ "<server_id>": { "host": ..., "port": ..., "username": ... } }`

```python
result = call_tool("ssh_list_servers", {})
# {"web-server": {"host": "192.168.1.10", "port": 22, "username": "deploy"}}
```

#### `ssh_list_allowed_commands(server_name)`

Lists the commands the **current client** is allowed to run on the given server (union of `default`, API-key, and network rules for that target). Does **not** apply `block_patterns` — a listed command can still be denied at execution time.

- **Parameters:** `server_name` (str) — configured server id
- **Returns:** JSON array of sorted, deduplicated base command names; `["*"]` if a wildcard applies

```python
result = call_tool("ssh_list_allowed_commands", {"server_name": "web-server"})
# ["cat", "df", "du", "free", "grep", "head", "hostname", ...]
```

#### `ssh_execute_command(server_name, command, timeout=30, sudo=False)`

Runs a command on the target over SSH.

- **Parameters:**
  - `server_name` (str, required) — configured server id
  - `command` (str, required) — the shell command to run
  - `timeout` (int, default `30`) — per-command timeout in seconds; clamped to `command_timeout_max`
  - `sudo` (bool, default `False`) — wrap with `sudo -S -p ''` (password taken from target config) or `sudo -n` (passwordless)
- **Returns:** stdout; if stderr is non-empty it is appended as `[STDERR]\n<stderr>`; a non-zero exit code appends `[EXIT: <code>]`; output at the configured limit appends `[OUTPUT TRUNCATED]`

```python
result = call_tool("ssh_execute_command", {
    "server_name": "web-server",
    "command": "uptime",
})
# " 07:12:33 up 10 days,  2:15,  1 user,  load average: 0.08, 0.03, 0.01"
```

> There is **no** `sudo_password` parameter — if sudo requires a password, it comes from the target's `password` field in `ssh-mcp-config.json`.

#### `ssh_download_file(server_name, remote_path)`

Downloads a file from the target via SFTP.

- **Parameters:**
  - `server_name` (str, required)
  - `remote_path` (str, required) — absolute remote path
- **Authorization:** equivalent to executing `cat <remote_path>`
- **Returns:** the file content decoded as UTF-8 (invalid bytes replaced)

```python
result = call_tool("ssh_download_file", {
    "server_name": "web-server",
    "remote_path": "/etc/hostname",
})
# "web-server\n"
```

#### `ssh_upload_file(server_name, remote_path, content, permissions="0644")`

Uploads a file to the target via SFTP.

- **Parameters:**
  - `server_name` (str, required)
  - `remote_path` (str, required) — absolute remote path, **must start with `/tmp/` or `/home/`**
  - `content` (str, required) — file contents (encoded UTF-8)
  - `permissions` (str, default `"0644"`) — octal permission string applied via `chmod`
- **Authorization:** equivalent to executing `tee <remote_path>`
- **Returns:** `OK: Uploaded <N> bytes to <path>`

```python
result = call_tool("ssh_upload_file", {
    "server_name": "web-server",
    "remote_path": "/tmp/backup.sql",
    "content": "CREATE TABLE ...;\n",
    "permissions": "0640",
})
# "OK: Uploaded 19 bytes to /tmp/backup.sql"
```

> **Upload restriction:** only paths under `/tmp/` or `/home/` are accepted. Anything else returns a `PathValidationError`.

### 4.4 Error responses

On failure a tool returns a JSON string with:

```jsonc
{
  "error": true,
  "error_type": "<ExceptionClassName>",
  "message": "<human-readable message>",
  "retryable": false,
  "request_id": "<correlation id>"
}
```

`retryable` is `true` for `SSHTimeoutError`. `error_type` is the concrete exception class name — e.g. `AuthorizationError`, `PathValidationError`, `FileTransferError` (e.g. content exceeding the 10 MiB upload limit), `SSHAuthenticationError`, `SSHTimeoutError`, or `MCPSSHError` for internal errors. Rate-limit violations do **not** return this shape — the middleware answers with HTTP `429` (see §4.5).

### 4.5 Rate limiting

Requests are rate-limited per client IP with a sliding window (fixed defaults: **60 requests / 60 s**, `/health` exempt). On violation the server returns HTTP `429` with a `Retry-After` header:

```jsonc
{
  "error": "Rate limit exceeded",
  "detail": "Too many requests from <ip>. Retry after <n> seconds."
}
```

### 4.6 Python client example

```python
import json
import requests

MCP_URL = "https://ssh-mcp.example.com/mcp"   # or http://localhost:8080/mcp
API_KEY = "my-secret-key"


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

print(call_tool("ssh_download_file", {
    "server_name": "web-server",
    "remote_path": "/etc/hostname",
}))
```

> The example uses `requests` directly. For the official SDK, point the MCP client at the same URL; it will send the `X-API-Key` header through the transport.

### 4.7 Metrics

Prometheus metrics are exposed at `GET /metrics` (also reachable through the Traefik entrypoint). All names are prefixed `mcpssh_` and live on a dedicated registry:

| Metric | Type | Labels |
|---|---|---|
| `mcpssh_requests_total` | Counter | `tool`, `status` (`success`/`error`/`denied`) |
| `mcpssh_ssh_connections_total` | Counter | `target` |
| `mcpssh_ssh_connection_duration_seconds` | Histogram | `target` |
| `mcpssh_auth_denials_total` | Counter | `reason` |
| `mcpssh_command_duration_seconds` | Histogram | `target` |
| `mcpssh_pool_active_connections` | Gauge | `target` |
| `mcpssh_pool_idle_connections` | Gauge | `target` |
| `mcpssh_pool_created_total` | Counter | `target` |

### 4.8 Logs

Structured JSONL logs are written to `LOG_DIR` (default `/logs`). Each entry includes `timestamp` (ISO 8601 UTC), `log_level`, `log_format_version`, `event`, `request_id` (correlation ID from `X-Request-ID` or generated), `source_ip`, `api_key_name`, `server_name`, `command`, `allowed`, `reason`, `matched_via`, `execution_time_ms`, `exit_code`, and optionally `output` (truncated to `max_log_output` characters). Command-execution entries also carry `sudo`. Files rotate at 10 MB keeping 5 backups; rotated files are gzipped when `compress_rotated` is enabled.

User-controlled `command`, `server_name`, and remote-path fields are newline-sanitized before logging — any run of `\r`/`\n` is collapsed to a single space, so a malicious value cannot forge or inject a spurious JSONL record.

#### 4.8.1 Configuration change / hot-reload events

Configuration lifecycle and hot-reload activity is logged through the following `event` names (all entries carry `config_path`):

| Event | Meaning | Extra fields |
|---|---|---|
| `config.load` | Initial config loaded at startup | `target_count` |
| `config.reload` | Config re-read from disk (hot-reload) | `success`, `trigger` (`manual`/`watchdog`/`polling`), `changed`, `changed_keys`, `targets_added`, `targets_removed`, `target_count` |
| `config.watcher.start` | Watcher started | `mode` (`watchdog`/`polling`), `polling_interval` |
| `config.watcher.stop` | Watcher stopped | `mode` |
| `config.watcher.debounced` | Change ignored inside debounce window | — |
| `config.watcher.reload_triggered` | Watchdog detected a change and is about to reload | — |
| `config.watcher.file_missing` | Polling watcher found the config file missing | — |
| `config.default_created` | Bundled `default-config.json` copied to the config dir | `source` |
| `config.fallback` | Server fell back to the bundled default config | `config_dir`, `config_path` |
| `config.migrated` | Config schema migration applied on load | `success`, `from_version`, `to_version` |
| `config.callback_error` | A registered config-change callback raised an exception | `error` |

Only key names and counts are logged for `config.reload` — secret values (passwords, private keys, key hashes) are never written to the log.

Config-change callbacks (`config_manager.on_config_change(...)`) run only **after** a successful reload has atomically swapped in the new data, so every callback observes the freshly committed configuration, never a partially-updated or stale state. Each callback runs in isolation: if one raises, the failure is logged as a `config.callback_error` event and the reload itself is not aborted nor are the remaining callbacks blocked. The current subscribers are the **authorization manager** (which rebuilds its rules snapshot) and the **SSH connection pool** (which closes idle connections for removed targets and refreshes those whose configuration changed).

---

## Additional Resources

- [`docs/SECURITY.md`](docs/SECURITY.md) — full security model (authorization chain, path validation, secrets, transport)
- [`compose.yaml`](compose.yaml) — Docker Compose deployment with Traefik labels
- [`Dockerfile`](Dockerfile) — multi-stage build, non-root runtime, SBOM stage
- [`default-config.json`](default-config.json) — bundled default configuration
- [`config.schema.json`](config.schema.json) — JSON Schema (Draft 2020-12) describing the config file format
- [`plans/`](plans/) — architecture, security, and feature plans (including planned improvements listed in §1)

## License

MIT — see the `LICENSE` file.
