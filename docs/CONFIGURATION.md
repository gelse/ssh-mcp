# Configuration Reference

ssh-mcp is configured via JSON files in the config directory, with
optional environment-variable overrides and a hot-reload watcher.

---

## Config directory

| Setting | Default |
|---------|---------|
| `CONFIG_DIR` env var | `/config` |
| Config file | `ssh-mcp-config.json` inside `CONFIG_DIR` |
| Secrets file | `secrets.json` inside `CONFIG_DIR` |

The config file path can be overridden with the
`MCP_SSH_CONFIG_PATH` environment variable.

Mount your config into the container:

```yaml
volumes:
  - ./config:/config
```

---

## ssh_targets

Each key is a target identifier (max 128 chars, `[a-zA-Z0-9._-]`).
Max 1000 targets per config.

The identifier is the **target**. MCP tools take it as their `server_name`
argument, rules list it under `targets`, and authorization results and logs
report it as `target` — one identifier under two names. A tool call for
`server_name: "web-1"` addresses the `web-1` key below; the value is never
a hostname or alias.

```json
{
  "ssh_targets": {
    "web-1": {
      "host": "10.0.1.10",
      "port": 22,
      "username": "deploy",
      "private_key": "/app/ssh_key",
      "password": null,
      "checkcommand": "echo ping"
    }
  }
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `host` | yes | — | SSH target hostname or IP |
| `port` | no | `22` | SSH target port |
| `username` | yes | — | SSH login user |
| `private_key` | no | `/app/ssh_key` | Path to private key inside container |
| `password` | no | `null` | SSH password (prefer `secrets.json`) |
| `checkcommand` | no | `echo ping` | Command run by connectivity check |

---

## block_patterns

Array of regex strings. If a command matches any pattern it is
denied regardless of other authorization layers.

```json
{
  "block_patterns": [
    "\\bsudo\\b",
    "\\brm\\s+-rf\\b",
    "\\bdd\\s+if=",
    "\\bshutdown\\b",
    "\\breboot\\b"
  ]
}
```

Max 500 patterns; max 10 000 chars per pattern. Patterns are
validated for ReDoS safety at load time.

---

## allowed_commands

Three sub-sections, all three required: `default` (all clients), `api_keys`
(per API key), and `networks` (per source CIDR). `api_keys` and `networks`
may be empty lists; `default` may not.

```json
{
  "allowed_commands": {
    "default": [
      {
        "targets": ["*"],
        "commands": ["hostname", "uptime", "free", "df", "systemctl"],
        "sudo_allowed": ["systemctl"]
      }
    ],
    "api_keys": [
      {
        "name": "deploy-key",
        "key_hash": "pbkdf2:sha256:100000$<salt>$<hash>",
        "rules": [
          {
            "targets": ["web-1"],
            "commands": ["systemctl", "journalctl"],
            "sudo_allowed": ["systemctl"]
          }
        ]
      }
    ],
    "networks": [
      {
        "name": "lan",
        "range": "10.0.0.0/8",
        "rules": [
          { "targets": ["*"], "commands": ["uptime", "free"] }
        ]
      }
    ]
  }
}
```

### Rule fields

`default` is a list of rules; each `api_keys` and `networks` entry wraps its
rules in a `rules` list.

| Field | Description |
|-------|-------------|
| `targets` | Target ids, or `*` for every target. Each id must exist in `ssh_targets`; prefixes such as `web-*` are not patterns and are rejected |
| `commands` | Command names, or `*` for every command. Matched against the base name — the first token of the command with any path stripped — so `systemctl` allows `systemctl status ssh` |
| `sudo_allowed` | Names from this rule's `commands` that may run with `sudo`, or `*` for all of them. A name absent from `commands` is rejected |

When `sudo=True` is passed to `ssh_execute_command`, the command's
base name must appear in `sudo_allowed` (or be `"*"`).

The host still needs matching `/etc/sudoers` entries for those commands.
The dashboard's **Sudoers** button on each SSH target generates a drop-in
from exactly these grants — the union of the default, API-key and network
rules for that target — with paths resolved on the host itself. See
[Config API & Dashboard](CONFIG-API.md#sudoers-generation).

### API key and network entry fields

| Field | Entry | Description |
|-------|-------|-------------|
| `name` | both | Unique name, shown in authorization results (`api_key:<name>`, `network:<name>`) |
| `key_hash` | `api_keys` | PBKDF2 (`pbkdf2:sha256:<iter>$<salt>$<hash>`) or legacy SHA-256 hash of the key; never the raw key |
| `range` | `networks` | IPv4 or IPv6 CIDR; overlapping ranges are rejected at load time |
| `rules` | both | Non-empty list of rules |

---

## settings

Runtime settings. `settings` must be present with `max_output_length` and
`command_timeout_max`; every other key falls back to its default from
[`lib/constants.py`](../lib/constants.py) and
[`default-config.json`](../default-config.json).

### General

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_output_length` | size | `50000` | Max chars returned to LLMs |
| `command_timeout_max` | int | `120` | Max seconds for command execution |
| `log_level` | str | `"INFO"` | Python log level |

### SSH connection

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `retry_max_attempts` | int | `3` | Max SSH connection attempts |
| `retry_backoff_base_seconds` | float | `1.0` | Base delay for exponential backoff |
| `circuit_breaker_failure_threshold` | int | `5` | Failures before circuit opens |
| `circuit_breaker_timeout_seconds` | float | `60.0` | Seconds before half-open probe |

### Connection pool

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `pool_max_connections_per_target` | int | `5` | Idle connections kept per target |
| `pool_idle_timeout_seconds` | float | `300.0` | Seconds before idle eviction |
| `pool_cleanup_interval_seconds` | float | `60.0` | Seconds between cleanup sweeps |
| `max_concurrent_ssh_connections` | int | `20` | Global concurrent connection cap |

### Logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_log_output` | int | `4096` | Max chars for output log field |
| `compress_rotated` | bool | `true` | gzip rotated log backups |

See [Observability](OBSERVABILITY.md) for log target configuration.

### Rate limiting

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rate_limit.enabled` | bool | `true` | Enable per-IP rate limiting |
| `rate_limit.max_requests_per_minute` | int | `60` | Max requests per window |
| `rate_limit.window_seconds` | float | `60.0` | Sliding window duration |
| `rate_limit.cleanup_interval_seconds` | float | `300.0` | GC interval for expired entries |

### SFTP

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sftp.sandbox_root` | str | `"/"` | Root directory for path validation |
| `sftp.max_path_length` | int | `4096` | Max remote path length (bytes) |

### Other

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `watcher_debounce_seconds` | float | `2.0` | Delay between config reloads |
| `trusted_proxies` | list | `[]` | Reverse proxy IPs for X-Forwarded-For |

---

## Secrets

SSH target passwords and API-key hashes should live in
`secrets.json` rather than the main config. The file uses a
parallel structure:

```json
{
  "version": 1,
  "ssh_targets": {
    "web-1": { "password": "s3cret" }
  },
  "api_keys": [
    { "name": "ci-bot", "key_hash": "pbkdf2:sha256:100000$..." }
  ]
}
```

### Environment-variable secrets

Set `MCP_SSH_SECRET_<IDENTIFIER>` env vars. Identifiers are
upper-cased with `-` replaced by `_`:

| Purpose | Env var pattern |
|---------|----------------|
| SSH target password | `MCP_SSH_SECRET_PASSWORD_<TARGET>` |
| API key hash | `MCP_SSH_SECRET_API_KEY_<KEY_NAME>` |

Example: key `ci-bot` → `MCP_SSH_SECRET_API_KEY_CI_BOT`

### Precedence

**Env vars > `secrets.json` > main config**

Values in `MCP_SSH_SECRET_*` env vars override `secrets.json`,
which overrides inline values in `ssh-mcp-config.json`.

---

## Environment-variable overrides

Non-secret settings can be overridden with `MCP_SSH_SETTING_<KEY>`
env vars. The key is upper-cased with `-` replaced by `_` and
coerced to the type declared in the settings table above.

| Purpose | Env var |
|---------|---------|
| Config file path | `MCP_SSH_CONFIG_PATH` |
| Log directory | `MCP_SSH_LOG_DIR` |
| Log level | `MCP_SSH_LOG_LEVEL` |
| SSH key path | `MCP_SSH_SSH_KEY` |
| Any setting | `MCP_SSH_SETTING_<KEY>` |

---

## Hot reload

The config watcher polls the config file every **15 seconds** with a
**2-second debounce**. Changes to `ssh-mcp-config.json` are
picked up automatically — no restart needed.

### What reloads

- SSH targets, block patterns, allowed commands, settings

### What does NOT reload

- Rate limiter settings (set at boot)
- Log target configuration
- Connection pool limits (set at boot)

To force a reload, touch the config file or restart the container.

---

## Schema & validation

The config is validated against
[`config.schema.json`](../config.schema.json) on every load and
write. The config-api test suite exercises validation paths:

```bash
cd config-api && ../.venv/bin/python -m pytest tests/
```

Invalid configs are rejected with descriptive error messages
including the failing field name.
