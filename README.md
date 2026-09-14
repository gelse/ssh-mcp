# ssh-mcp

A centralized MCP gateway that gives AI agents controlled SSH
access over Streamable HTTP.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker)](https://ghcr.io/gelse/ssh-mcp)
[![MCP](https://img.shields.io/badge/MCP-streamable--HTTP-green.svg)](https://modelcontextprotocol.io/)
[![Security](https://img.shields.io/badge/security-layered--auth-orange.svg)](docs/SECURITY.md)
[![M8ven Live Monitored](https://m8ven.ai/badge/mcp/gelse-ssh-mcp-btei1o)](https://m8ven.ai/mcp/gelse-ssh-mcp-btei1o)

---

## What problem does this solve?

Most MCP SSH servers run as local stdio processes — one per
client, with no shared state, no centralized authorization, and
no audit trail. When multiple AI agents need SSH access, each
manages its own SSH keys and runs its own process. This creates:

- **No centralized access control** — every client decides
  what it can run
- **No audit trail** — commands are invisible to the ops team
- **SSH key sprawl** — keys scattered across every agent machine
- **No rate limiting** — a runaway agent can overwhelm a target

**ssh-mcp** solves this by deploying a single HTTP gateway. All
clients connect to it; it connects to your SSH targets.
Authorization, rate limiting, connection pooling, and audit
logging happen in one place.

---

## Quick Start

### Using the pre-built image (recommended)

```bash
docker compose pull
docker compose up -d
```

The image is published at `ghcr.io/gelse/ssh-mcp:latest`.
The compose file maps host port **9080** to container port 8080.

Verify the server is running:

```bash
curl http://localhost:9080/health
# → {"status": "ok"}
```

Create a minimal config in `config/ssh-mcp-config.json`:

```json
{
  "version": 1,
  "ssh_targets": {
    "my-server": {
      "host": "10.0.1.10",
      "username": "deploy"
    }
  },
  "allowed_commands": {
    "default": [
      {
        "targets": ["*"],
        "commands": ["hostname", "uptime", "free", "df"]
      }
    ]
  }
}
```

Generate an API key hash and add it to your config or
`secrets.json` (see [Configuration](docs/CONFIGURATION.md#secrets)).

<details>
<summary>Build locally instead</summary>

```bash
make build
docker compose up -d --build
```
</details>

---

## What you can do (tools)

Six MCP tools are available over Streamable HTTP:

| Tool | Description |
|------|-------------|
| `ssh_list_servers` | List configured SSH targets |
| `ssh_list_allowed_commands` | Show allowed commands for a target |
| `ssh_execute_command` | Execute a command on a remote server |
| `ssh_check_connection` | Test SSH connectivity to a target |
| `ssh_download_file` | Download a file via SFTP |
| `ssh_upload_file` | Upload a file via SFTP |

### Tool Naming Convention

All tools follow the pattern `ssh_<verb>_<noun>`:

- `ssh_list_servers` — list resources
- `ssh_list_allowed_commands` — list permissions
- `ssh_execute_command` — perform an action
- `ssh_check_connection` — verify connectivity
- `ssh_download_file` / `ssh_upload_file` — file transfer

See [`examples/README.md`](examples/README.md) for usage examples
including curl commands and Python client code.

---

## What's configurable

ssh-mcp is configured via JSON files with hot-reload
(15 s poll, 2 s debounce). Key areas:

| Area | Details |
|------|---------|
| SSH targets | Host, port, username, key, password |
| Command policies | Block patterns, per-key/network allowlists |
| Connection pool | Max connections, idle timeout, concurrency |
| Rate limiting | Per-IP sliding window (default 60 req/min) |
| Logging | JSONL with rotation, gzip, multiple targets |
| SFTP | Sandbox root, path length limits |

Full reference: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)

| File | Purpose |
|------|---------|
| `ssh-mcp-config.json` | Main config |
| `config.schema.json` | JSON Schema for validation |
| `secrets.json` | Passwords and API key hashes |
| `MCP_SSH_*` env vars | Overrides for any setting |

---

## Why not just raw SSH / other MCP servers?

ssh-mcp adds a **layered authorization chain** (9 ordered layers)
between every client request and every SSH command. Per-API-key and
per-network rules let different agents get different permissions on
different servers — without touching the underlying SSH accounts.

Additional protections:

- **Circuit breakers** isolate failing targets with exponential
  backoff
- **Rate limiting** prevents runaway agents from overwhelming hosts
- **Structured audit logs** trace every command, client, IP, and
  authorization decision
- **Connection pooling** reuses SSH sessions across requests
- **Input sanitization** and **dangerous-pattern detection** block
  shell injection attempts

Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md)
Security model: [`docs/SECURITY.md`](docs/SECURITY.md)

---

## What it is NOT

- **Not an interactive shell** — commands are executed
  individually with structured output
- **Not a file manager** — SFTP supports single-file download
  and upload only (no directory listing or recursive transfer)
- **Not a firewall / network ACL** — authorization is
  command-level, not network-level
- **Does not reduce SSH account privileges** — if a command is
  allowed, the SSH user executes it with whatever privileges
  that account has

---

## Not yet / known gaps

**Fixable with contribution:**

- SFTP is single-file only — no directory listing or recursive
  transfer
- No TLS termination — run Traefik or nginx in front
- No OAuth or mTLS app-layer authentication
- Rate limiter settings are not hot-reloadable (set at boot)

**Architectural:**

- Config API dashboard login sessions are in-memory only — they
  don't survive restarts and the API is single-instance (config
  changes themselves persist to the config file normally)
- No tamper protection for audit logs

---

## Observability

- **Health:** `GET /health` — returns `{"status": "ok"}`
- **Metrics:** `GET /metrics` — Prometheus exposition format
- **Logging:** Structured JSONL with request correlation

Full reference: [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md)

---

## Config API & Dashboard

An optional web dashboard for managing configuration without
editing JSON files. Enable with `CONFIG_API_ENABLED=true`.

Full reference: [`docs/CONFIG-API.md`](docs/CONFIG-API.md)

---

## FAQ

### Dashboard returns 401 over HTTP

The session cookie defaults to `Secure` (HTTPS only). For local
HTTP testing, set:

```yaml
environment:
  - CONFIG_API_SESSION_COOKIE_SECURE=false
```

Then restart the container.

### How do MCP clients connect?

Connect to `http://host:9080/mcp` using the Streamable HTTP
transport. Pass your API key via `X-API-Key` or
`Authorization: Bearer` header.

### How do I generate an API key hash?

```bash
docker compose exec mcp-ssh python -c \
  "from lib.crypto import hash_api_key; print(hash_api_key('your-key'))"
# → pbkdf2:sha256:100000$<salt>$<hash>
```

Or use the hash utility in the Config API dashboard.

### How does hot reload work?

The config file is polled every 15 seconds with a 2-second
debounce. Changes to targets, commands, and settings take effect
without restart. Rate limiter and log target settings require a
restart.

### Why was my command denied?

Commands are evaluated through a 9-layer authorization chain.
The `matched_via` field in logs shows which layer denied.
See [Security Model](docs/SECURITY.md) for the full chain.

### How does rate limiting work?

Per-IP sliding window, default 60 requests per 60 seconds.
Exceeding the limit returns HTTP 503. Configure via
`settings.rate_limit` in the config file.

### Where do logs go?

Logs are written to the `/logs` volume (mapped from `./logs`).
The active log file is `ssh-mcp.log` in JSONL format with
optional gzip rotation.

### Troubleshooting basics

```bash
# Check server health
curl http://localhost:9080/health

# Validate config
make config-test

# Check logs
docker compose logs mcp-ssh
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System design and data flow |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Security model and threat analysis |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Full config reference |
| [`docs/CONFIG-API.md`](docs/CONFIG-API.md) | Config API & dashboard |
| [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) | Health, metrics, logging |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Development and contribution guide |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |
| [`examples/`](examples/) | Config examples and client code |

---

## Development

```bash
# Unit tests
make test

# Integration tests (builds Docker image)
make integrationtest
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full development
guide, coding conventions, and PR workflow.

---

## Roadmap

No public roadmap. See
[Not yet / known gaps](#not-yet--known-gaps) for current
limitations and opportunities.

---

## License

[MIT](LICENSE)
