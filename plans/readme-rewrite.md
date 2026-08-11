# README Rewrite Plan

## Source-verified Facts (every claim confirmed against code)

### Tools (exactly 5)
| Tool | Signature |
|------|-----------|
| `ssh_list_servers()` | no parameters |
| `ssh_list_allowed_commands(server_name: str)` | single string |
| `ssh_execute_command(server_name: str, command: str, timeout: int = 30, sudo: bool = False)` | **NO `sudo_password` parameter** |
| `ssh_download_file(server_name: str, remote_path: str)` | returns file content string |
| `ssh_upload_file(server_name: str, remote_path: str, content: str, permissions: str = "0644")` | parameter is `permissions` not `mode` |

### Environment Variables (exactly 4)
| Variable | Maps to | Default |
|----------|---------|---------|
| `CONFIG_DIR` | `--config` | `./config` |
| `SSH_KEY_PATH` | `--ssh-key` | `./config/ssh_key` |
| `LOG_DIR` | `--log-dir` | `./logs` |
| `MAX_OUTPUT_LENGTH` | `--max-output` | `50000` |

**NOT read by code**: `API_KEYS`, `SSH_TARGETS_FILE`, `SSL_CERT_PATH`, `SSL_KEY_PATH`, `TRAEFIK_HOST`, `TRAEFIK_PORT`, `TRAEFIK_ENTRYPOINTS`, `CONFIG_PATH`

### Configuration File Structure
- File: `<CONFIG_DIR>/ssh-mcp-config.json`
- Top-level keys: `version`, `ssh_targets`, `block_patterns`, `allowed_commands`, `settings`
- `allowed_commands.api_keys`: **list** of `{name, key_hash, rules}` objects (NOT dict/object)
- `allowed_commands.networks`: list of `{name, range, rules}` objects
- `key_hash` format: `sha256:<hex>` or `pbkdf2:sha256:<iter>$<salt>$<hash>`

### Settings (flat keys, not dot notation)
| Setting | Default | Unit |
|---------|---------|------|
| `max_output_length` | 50000 | bytes |
| `command_timeout_max` | 120 | seconds |
| `retry_max_attempts` | 3 | count |
| `retry_backoff_base_seconds` | 1.0 | seconds |
| `circuit_breaker_failure_threshold` | 5 | count |
| `circuit_breaker_timeout_seconds` | 60 | seconds |
| `log_level` | "INFO" | string |
| `max_log_output` | 4096 | chars |
| `compress_rotated` | true | bool |
| `pool_max_connections_per_target` | 5 | count |
| `pool_idle_timeout_seconds` | 300 | seconds |
| `pool_cleanup_interval_seconds` | 60 | seconds |

### Metrics (actual exposed — 8 total)
- `mcpssh_requests_total` — counter with `tool` and `status` labels
- `mcpssh_ssh_connections_total` — counter with `target` label
- `mcpssh_ssh_connection_duration_seconds` — histogram with `target` label
- `mcpssh_auth_denials_total` — counter with `reason` label
- `mcpssh_command_duration_seconds` — histogram with `target` label
- `mcpssh_pool_active_connections` — gauge with `target` label
- `mcpssh_pool_idle_connections` — gauge with `target` label
- `mcpssh_pool_created_total` — counter with `target` label

**NOT exposed**: circuit breaker state, rate limiter counters (despite README claims)

### Planned Features (from plans/11a)
- Separate `secrets.json` file
- `MCP_SSH_SETTING_*` env var overrides
- Schema version migration
- Duplicate target detection
- File permission validation

---

## Proposed README Structure

### Section 1: Summary
- One-paragraph project description (SSH MCP server for Homelab, 5 tools, streamable HTTP)
- Feature list (ONLY implemented features):
  - 5 MCP tools for SSH command execution and SFTP file transfer
  - Layered command authorization (block patterns → dangerous patterns → default → API key → network → deny)
  - PBKDF2-HMAC-SHA256 API key hashing with per-key random salt
  - SSH connection pooling with configurable limits
  - Sliding-window rate limiting per client IP
  - Circuit breaker pattern for SSH target resilience
  - Retry with exponential backoff
  - Structured JSONL logging with rotation and compression
  - Hot-reload configuration (no restart needed)
  - Prometheus metrics endpoint
  - Health check endpoint
  - Sudo support (password from target config or passwordless)
  - SFTP path traversal prevention (7-layer validation)
  - Non-root Docker container
- **Planned Improvements** (clearly marked as not yet implemented):
  - Separate secrets file (`secrets.json`)
  - Environment variable setting overrides (`MCP_SSH_SETTING_*`)
  - Schema version migration
  - Duplicate SSH target detection
  - File permission validation

### Section 2: Configuration
- Config file location: `config/ssh-mcp-config.json`
- API key generation workflow (using `hash_api_key()` from `lib/crypto.py`)
- Full annotated config example with all 5 sections
- Correct `api_keys` format (list of objects, not dict)
- Correct `networks` format (list of objects with `range` field)
- Correct settings keys (flat names)
- Environment variables table (only the 4 that actually work)
- CLI flags table (only the 4 that exist)
- Use-case examples (admin key with broad rules, read-only key, network-restricted access)

### Section 3: Deployment
- Prerequisites (Docker, SSH key pair)
- Step-by-step Docker deployment:
  1. Create config directory and SSH key
  2. Create `ssh-mcp-config.json`
  3. Hash API keys
  4. Start with `docker compose up -d`
- Volume mounts (`./config:/config`, `./logs:/logs`)
- Traefik integration (labels in compose, note these are compose-level not server env vars)
- Health check (`/health`)
- Makefile commands (`make build`, `make up`, `make down`, `make test`, `make integrationtest`, `make clean-test`)

### Section 4: User Guide
- Tool reference with correct signatures
- Each tool: signature, description, parameters table, response format, example
- Upload path restriction note (`/tmp/` or `/home/` only)
- Python MCP client example
- Error response format
- Health and metrics endpoints
- Log format and location

---

## 14 Inaccuracies to Fix

| # | Issue | Fix |
|---|-------|-----|
| 1 | `API_KEYS` env var documented | Remove; direct to `allowed_commands.api_keys` in config |
| 2 | `.env` file loading documented | Remove; project never imports `dotenv` |
| 3 | `api_keys` shown as dict/object | Show correct list-of-objects format |
| 4 | `SSH_TARGETS_FILE` env var | Remove from table |
| 5 | `SSL_CERT_PATH`, `SSL_KEY_PATH` env vars | Remove from table (not used by Python code) |
| 6 | `TRAEFIK_*` env vars in server table | Clarify these are compose interpolation only |
| 7 | `CONFIG_PATH` instead of `CONFIG_DIR` | Fix to `CONFIG_DIR` |
| 8 | `rate_limit.requests` / `rate_limit.window` | Remove entirely — `settings.rate_limit` is rejected by validation (`ALLOWED_SETTINGS` has no `rate_limit`); rate limiting always uses fixed defaults (60 req/min, 60 s window, 300 s cleanup) |
| 9 | `retry_backoff_max` setting | Remove (doesn't exist) |
| 10 | `pool.max_size`, `pool.max_age`, `pool.idle_timeout` | Fix to actual flat settings and correct defaults |
| 11 | `sudo_password` parameter on `ssh_execute_command` | Remove; sudo password comes from target config |
| 12 | `mode` parameter on `ssh_upload_file` | Fix to `permissions` |
| 13 | Quick Start step 4 (create `.env` / export `API_KEYS`) | Replace with API key hashing + config workflow |
| 14 | Metrics claim circuit-breaker/rate-limiter stats | Remove; document the 8 real metrics (incl. pool gauges) |
