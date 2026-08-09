# mcp-ssh

MCP server that provides remote SSH command execution and file transfer capabilities. Deploy as a Docker container behind a reverse proxy to give AI agents (Claude Desktop, Continue, etc.) secure, audited access to your SSH infrastructure.

## Features

- **5 MCP tools** — list servers, list allowed commands, execute commands, download files, upload files
- **Layered authorization** — block patterns → default allowlist → API key rules → network rules
- **Connection pooling** — persistent SSH connections with configurable pool limits
- **Rate limiting** — sliding-window rate limiter (60 req/min default)
- **Circuit breaker** — automatic failure detection and graceful degradation
- **Structured logging** — JSONL logs with rotation, correlation IDs, and truncation
- **Prometheus metrics** — request counts, durations, errors, pool stats
- **Hot-reload** — configuration changes picked up without restart

## Prerequisites

- Docker and Docker Compose
- An SSH keypair for authenticating to your remote hosts
- A reverse proxy with TLS termination (Traefik configuration included)

## Quick Start

### 1. Prepare configuration directory

```bash
mkdir -p config logs
```

### 2. Create SSH key

Place your SSH private key at `config/ssh_key`:

```bash
cp ~/.ssh/id_ed25519 config/ssh_key
chmod 600 config/ssh_key
```

### 3. Create configuration file

Copy the default config and edit it for your targets:

```bash
cp default-config.json config/ssh-mcp-config.json
```

Edit `config/ssh-mcp-config.json` to define your SSH targets, allowed commands, and settings. See [Configuration](#configuration) below.

### 4. Set API keys

Create a `.env` file or export the variable directly:

```bash
export API_KEYS='{"my-client-key": "My Client"}'
```

The key is the API key string clients will send; the value is a human-readable name used in logs and authorization rules.

### 5. Start the server

```bash
docker compose up -d
```

### 6. Verify

```bash
curl http://localhost:8080/health
```

Expected response: `{"status": "healthy"}`

## Configuration

The configuration file (`config/ssh-mcp-config.json`) has four sections:

### `ssh_targets`

A dictionary of named SSH targets. Each target supports:

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | Yes | Hostname or IP address |
| `port` | integer | Yes | SSH port (typically 22) |
| `username` | string | Yes | SSH username |
| `private_key` | string | No | Path to SSH private key for this target (overrides global key) |
| `password` | string | No | SSH password (key-based auth preferred) |

```json
{
  "ssh_targets": {
    "web-server": {
      "host": "192.168.1.10",
      "port": 22,
      "username": "deploy",
      "private_key": "/config/keys/web_server_key"
    },
    "db-server": {
      "host": "db.internal",
      "port": 2222,
      "username": "admin"
    }
  }
}
```

If no `private_key` is specified for a target, the global SSH key at `SSH_KEY_PATH` (default: `/config/ssh_key`) is used.

### `block_patterns`

An array of regex patterns. Any command matching a block pattern is rejected immediately, regardless of authorization rules.

```json
{
  "block_patterns": [
    "rm\\s+-rf\\s+/",
    "mkfs\\..*",
    "dd\\s+if=",
    ">\\s*/dev/sd[a-z]",
    "shutdown",
    "reboot",
    ":\\s*\\(\\)\\s*\\{",
    "chmod\\s+777"
  ]
}
```

### `allowed_commands`

Layered authorization controlling which commands can be executed on which targets. Three layers, evaluated in order:

| Layer | Key | Description |
|---|---|---|
| Default | `default` | Baseline rules that apply to all callers |
| API Key | `api_keys` | Per-API-key overrides (keyed by API key name) |
| Network | `networks` | Per-CIDR overrides (keyed by network CIDR) |

Each rule contains:

| Field | Type | Description |
|---|---|---|
| `targets` | string[] | SSH target names this rule applies to |
| `commands` | string[] | Allowed command patterns (supports `*` wildcard) |

```json
{
  "allowed_commands": {
    "default": [
      {
        "targets": ["web-server"],
        "commands": ["docker ps", "systemctl status *", "tail *", "df -h", "free -m"]
      },
      {
        "targets": ["db-server"],
        "commands": ["pg_lsclusters", "systemctl status postgresql*"]
      }
    ],
    "api_keys": {
      "Admin Key": [
        {
          "targets": ["*"],
          "commands": ["*"]
        }
      ]
    }
  }
}
```

### `settings`

| Setting | Default | Description |
|---|---|---|
| `max_output_length` | 50000 | Maximum bytes of command output returned |
| `command_timeout_max` | 120 | Maximum seconds a command can run |
| `retry_max_attempts` | 3 | Maximum retry attempts for transient failures |
| `retry_backoff_base` | 2.0 | Exponential backoff multiplier |
| `retry_backoff_max` | 30.0 | Maximum backoff seconds between retries |
| `circuit_breaker.failure_threshold` | 5 | Consecutive failures before circuit opens |
| `circuit_breaker.recovery_timeout` | 60 | Seconds before attempting recovery |
| `circuit_breaker.half_open_max` | 3 | Max requests allowed in half-open state |
| `pool.max_size` | 10 | Max SSH connections per target |
| `pool.max_age` | 300 | Max connection lifetime in seconds |
| `pool.idle_timeout` | 120 | Idle seconds before connection is closed |
| `log_level` | "INFO" | Log level (DEBUG, INFO, WARNING, ERROR) |
| `rate_limit.requests` | 60 | Max requests per window |
| `rate_limit.window` | 60 | Sliding window size in seconds |

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `API_KEYS` | Yes | — | JSON map of API key → display name |
| `SSH_KEY_PATH` | No | `/config/ssh_key` | Path to default SSH private key |
| `CONFIG_PATH` | No | `/config` | Directory containing `ssh-mcp-config.json` |
| `SSH_TARGETS_FILE` | No | `ssh-mcp-config.json` | Config filename (within `CONFIG_PATH`) |
| `LOG_DIR` | No | `/logs` | Directory for JSONL log files |
| `SSL_CERT_PATH` | No | — | Path to TLS certificate (for direct TLS) |
| `SSL_KEY_PATH` | No | — | Path to TLS private key (for direct TLS) |
| `TRAEFIK_HOST` | No | — | Traefik routing hostname |
| `TRAEFIK_PORT` | No | `8080` | Internal application port |
| `TRAEFIK_ENTRYPOINTS` | No | `websecure` | Traefik entrypoint name |

## Traefik Integration

The included [`compose.yaml`](compose.yaml) configures Traefik labels for automatic routing and TLS:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.mcp-ssh.rule=Host(`${TRAEFIK_HOST}`)"
  - "traefik.http.routers.mcp-ssh.entrypoints=${TRAEFIK_ENTRYPOINTS:-websecure}"
  - "traefik.http.routers.mcp-ssh.tls=true"
  - "traefik.http.services.mcp-ssh.loadbalancer.server.port=${TRAEFIK_PORT:-8080}"
```

Ensure your Traefik instance is on the `traefik` network and that the `websecure` entrypoint has a TLS certificate resolver configured.

## Usage

Clients interact with the server via JSON-RPC over HTTP. The five available MCP tools are described below.

All requests must include the `X-API-Key` header with a valid API key.

### `ssh_list_servers`

List all configured SSH target names.

**Parameters:** None

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-client-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "ssh_list_servers",
      "arguments": {}
    }
  }'
```

### `ssh_list_allowed_commands`

List commands authorized for a specific SSH target.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `server_name` | string | Yes | Name of the SSH target |

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-client-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "ssh_list_allowed_commands",
      "arguments": {"server_name": "web-server"}
    }
  }'
```

### `ssh_execute_command`

Execute a command on a remote host.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `server_name` | string | Yes | Name of the SSH target |
| `command` | string | Yes | Command to execute |
| `sudo` | boolean | No | Execute with sudo (default: false) |
| `sudo_password` | string | No | Sudo password (if required) |
| `timeout` | integer | No | Command timeout in seconds (max: `command_timeout_max`) |

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-client-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "ssh_execute_command",
      "arguments": {
        "server_name": "web-server",
        "command": "docker ps --format \"{{.Names}}\t{{.Status}}\""
      }
    }
  }'
```

### `ssh_download_file`

Download a file from a remote host via SFTP. The file content is returned as a base64-encoded string.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `server_name` | string | Yes | Name of the SSH target |
| `remote_path` | string | Yes | Absolute path to the file on the remote host |

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-client-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "ssh_download_file",
      "arguments": {
        "server_name": "web-server",
        "remote_path": "/var/log/nginx/access.log"
      }
    }
  }'
```

### `ssh_upload_file`

Upload content to a remote host via SFTP. Content is provided as a UTF-8 string and written to the specified path.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `server_name` | string | Yes | Name of the SSH target |
| `remote_path` | string | Yes | Absolute destination path on the remote host |
| `content` | string | Yes | File content to write |
| `mode` | string | No | File permissions in octal (e.g., "0644") |

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-client-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "ssh_upload_file",
      "arguments": {
        "server_name": "web-server",
        "remote_path": "/tmp/deploy.sh",
        "content": "#!/bin/bash\necho deployed",
        "mode": "0755"
      }
    }
  }'
```

### Python MCP Client

```python
import json
import requests

MCP_URL = "https://mcp-ssh.example.com/mcp"
API_KEY = "my-client-key"


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


# List servers
print(call_tool("ssh_list_servers", {}))

# Execute a command
print(call_tool("ssh_execute_command", {
    "server_name": "web-server",
    "command": "uptime",
}))

# Download a file
print(call_tool("ssh_download_file", {
    "server_name": "web-server",
    "remote_path": "/etc/hostname",
}))
```

## Health & Monitoring

### Health Endpoint

```
GET /health
```

Returns `{"status": "healthy"}` with HTTP 200 when the server is running and able to accept connections.

### Prometheus Metrics

Metrics are exposed at the Traefik entrypoint and include:

- Request counts by tool name and status
- Request duration histograms
- SSH connection pool statistics
- Circuit breaker state per target
- Rate limiter counters

### Logs

Structured JSONL logs are written to the `LOG_DIR` (default: `/logs`). Each log entry includes:

- `timestamp` — ISO 8601 UTC
- `level` — DEBUG, INFO, WARNING, ERROR
- `correlation_id` — unique per-request identifier
- `tool` — MCP tool name
- `server_name` — SSH target
- `api_key_name` — authenticated client identity
- `client_ip` — originating IP address
- `duration_ms` — request processing time

Logs rotate at 10 MB with 5 backups retained.

## Makefile Commands

| Command | Description |
|---|---|
| `make build` | Build the Docker image |
| `make up` | Start the container with Docker Compose |
| `make down` | Stop and remove the container |
| `make test` | Run unit tests (excludes integration) |
| `make integrationtest` | Build test image and run integration tests |
| `make clean-test` | Remove test artifacts and containers |

## Security

mcp-ssh implements multiple security layers:

- **TLS** — All traffic encrypted via Traefik reverse proxy (required for production)
- **API Key Authentication** — PBKDF2-SHA256 hashed keys with constant-time comparison
- **Command Authorization** — Regex block patterns prevent dangerous commands; layered allowlists control per-target access
- **SFTP Path Traversal Prevention** — 7-layer defense against path traversal attacks
- **Rate Limiting** — Sliding-window rate limiter (60 req/min per client IP by default)
- **Secure Defaults** — Non-root container user, pinned dependencies, SBOM generation

For full details, see [`docs/SECURITY.md`](docs/SECURITY.md).

## License

MIT — see `LICENSE` file.
