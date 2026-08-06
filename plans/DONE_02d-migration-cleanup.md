# Plan 02d: Migration & Cleanup — default-config.json, Docker, Compose, and End-to-End Tests

## Parent: [Plan 02 — External Config File with Watching](plans/02-config-file.md)
## Dependencies: [Plan 02a](plans/02a-config-core.md), [Plan 02b](plans/02b-hot-reload.md), [Plan 02c](plans/02c-server-integration.md)

---

## Scope

This sub-plan handles the final integration and cleanup:
- Create the bundled [`default-config.json`](default-config.json) with all 13 existing SSH targets, current allowed commands, and block patterns
- Update [`Dockerfile`](Dockerfile) to include `default-config.json` and `lib/`
- Update [`compose.yaml`](compose.yaml) to mount config directory and remove `ssh-servers.json` mount
- Remove [`ssh-servers.json`](ssh-servers.json)
- Write end-to-end tests that verify the full config pipeline

**Requires**: All code from Plans 02a, 02b, and 02c must be implemented and working.

---

## [`default-config.json`](default-config.json) — Bundled Default Config

This file is shipped in the Docker image at `/app/default-config.json`. On first startup, if no config exists in `<CONFIG_DIR>`, `ConfigManager._ensure_default_config()` copies this file to `<CONFIG_DIR>/ssh-mcp-config.json`.

### Migration Rules

From the old [`ssh-servers.json`](ssh-servers.json):
- `privateKey` → `private_key` (snake_case)
- `/host/data/ssh_key` → `/app/ssh_key` (new mount path from Plan 01)
- All 13 entries preserved with their existing host/port/username values
- `solaxpi` retains both `private_key` and `password` ("tabasco")

From the old hardcoded lists in [`server.py`](server.py:22-43):
- `ALLOWED_COMMANDS` → `allowed_commands.default[0].commands`
- `BLOCK_PATTERNS` → `block_patterns` (with double-escaping for JSON)

### Full Content

```json
{
  "version": 1,
  "ssh_targets": {
    "knubbel": {
      "host": "knubbel.gelse.local",
      "port": 22,
      "username": "ansible",
      "private_key": "/app/ssh_key"
    },
    "frtdf": {
      "host": "frtdf.gelse.net",
      "port": 33,
      "username": "root",
      "private_key": "/app/ssh_key"
    },
    "eli-kiosk": {
      "host": "elikiosk.gelse.local",
      "port": 22,
      "username": "werner",
      "private_key": "/app/ssh_key"
    },
    "brainbox": {
      "host": "10.42.43.13",
      "port": 22,
      "username": "werner",
      "private_key": "/app/ssh_key"
    },
    "mail": {
      "host": "mail.gelse.net",
      "port": 33,
      "username": "werner",
      "private_key": "/app/ssh_key"
    },
    "mail-root": {
      "host": "mail.gelse.net",
      "port": 33,
      "username": "root",
      "private_key": "/app/ssh_key"
    },
    "piprint": {
      "host": "10.42.43.14",
      "port": 22,
      "username": "dietpi",
      "private_key": "/app/ssh_key"
    },
    "hole": {
      "host": "10.42.43.2",
      "port": 22,
      "username": "dietpi",
      "private_key": "/app/ssh_key"
    },
    "storagebox2": {
      "host": "u300203.your-storagebox.de",
      "port": 23,
      "username": "u300203",
      "private_key": "/app/ssh_key"
    },
    "home": {
      "host": "home.gelse.local",
      "port": 22,
      "username": "root",
      "private_key": "/app/ssh_key"
    },
    "solaxpi": {
      "host": "solaxpi.gelse.local",
      "port": 22,
      "username": "dietpi",
      "password": "tabasco",
      "private_key": "/app/ssh_key"
    },
    "OVHCloud": {
      "host": "vps-6abf0d69.vps.ovh.net",
      "port": 22,
      "username": "debian",
      "private_key": "/app/ssh_key"
    }
  },
  "block_patterns": [
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
  ],
  "allowed_commands": {
    "default": [
      {
        "targets": ["*"],
        "commands": [
          "hostname", "uptime", "free", "df", "du",
          "docker", "docker-compose", "systemctl", "journalctl",
          "kubectl", "ps", "top", "htop",
          "ls", "cat", "head", "tail", "grep", "find", "wc",
          "ss", "netstat", "ip", "ping",
          "curl", "wget", "pihole",
          "echo", "date", "who", "id",
          "sqlite3", "zpool", "zfs",
          "lsof", "mount", "smartctl", "lsblk", "nvme", "lsscsi"
        ]
      }
    ],
    "api_keys": [],
    "networks": []
  },
  "settings": {
    "max_output_length": 50000,
    "command_timeout_max": 120
  }
}
```

---

## Changes to [`Dockerfile`](Dockerfile)

### Current state (lines 12–13):
```dockerfile
COPY server.py /app/
COPY lib/ /app/lib/
```

### New state:
```dockerfile
COPY server.py /app/
COPY lib/ /app/lib/
COPY default-config.json /app/
```

The `lib/` directory copy already exists and is correct. Only `default-config.json` needs to be added.

### `.dockerignore` — verify no exclusion

Check that [`.dockerignore`](.dockerignore) does not exclude `*.json` files or `default-config.json`. If it does, add an exception.

---

## Changes to [`compose.yaml`](compose.yaml)

### Current mounts (lines 9–14):
```yaml
volumes:
  - ./config:/config
  - ./logs:/logs
  - ./ssh_key:/app/ssh_key:ro
  - ./ssh_key.pub:/app/ssh_key.pub:ro
  - ./ssh-servers.json:/app/ssh-servers.json:ro
```

### New mounts:
```yaml
volumes:
  - ./config:/config
  - ./logs:/logs
  - ./ssh_key:/app/ssh_key:ro
  - ./ssh_key.pub:/app/ssh_key.pub:ro
```

**Remove**: `- ./ssh-servers.json:/app/ssh-servers.json:ro`

The `CONFIG_DIR` and `LOG_DIR` environment variables are already present (lines 16–17) and remain unchanged.

---

## Remove [`ssh-servers.json`](ssh-servers.json)

After verifying the server works with the new config, delete the old `ssh-servers.json` file.

---

## End-to-End Tests

Create [`tests/test_e2e_config.py`](tests/test_e2e_config.py) for full-pipeline tests:

### Test Cases

1. **Default config creation**: Start with empty config dir → verify `ssh-mcp-config.json` is created from `default-config.json`
2. **Full validation pass**: Load the bundled `default-config.json` → verify all 13 targets are present, all commands, all block patterns
3. **Hot-reload end-to-end**: Start with valid config → modify file with new target → verify `ssh_list_servers()` includes new target after polling interval
4. **Hot-reload with invalid config**: Start with valid config → write invalid JSON → verify `ssh_list_servers()` still returns old data
5. **Config directory permission**: Verify `_ensure_default_config()` creates files with `0o600` permissions
6. **Docker startup simulation**: Verify `CONFIG_DIR` env var is respected, default config is created, and server starts

---

## Files to Create/Modify/Remove

| File | Action | Purpose |
|------|--------|---------|
| [`default-config.json`](default-config.json) | **Create** | Bundled default config with all 13 SSH targets, commands, block patterns |
| [`Dockerfile`](Dockerfile) | **Modify** | Add `COPY default-config.json /app/` |
| [`compose.yaml`](compose.yaml) | **Modify** | Remove `ssh-servers.json` volume mount |
| [`ssh-servers.json`](ssh-servers.json) | **Delete** | Replaced by `ssh_targets` section in unified config |
| [`tests/test_e2e_config.py`](tests/test_e2e_config.py) | **Create** | End-to-end tests for full config pipeline |

---

## Implementation Steps

1. Create [`default-config.json`](default-config.json) with the full content shown above (all 13 targets, all commands, all block patterns with double-escaping, settings)
2. Verify `.dockerignore` does not exclude `default-config.json` — read the file and adjust if needed
3. Update [`Dockerfile`](Dockerfile): add `COPY default-config.json /app/` after the existing `COPY lib/` line
4. Update [`compose.yaml`](compose.yaml): remove the `./ssh-servers.json:/app/ssh-servers.json:ro` line from `volumes`
5. Run the server locally (not in Docker) to verify it starts with the new config:
   - `mkdir -p /tmp/test-config && CONFIG_DIR=/tmp/test-config python server.py`
   - Verify `/tmp/test-config/ssh-mcp-config.json` was created
   - Verify server responds to health check
6. Build and test Docker image:
   - `docker compose build`
   - `docker compose up -d`
   - Verify health check passes
   - Verify `ssh_list_servers` returns all 13 targets
7. Delete [`ssh-servers.json`](ssh-servers.json)
8. Write and run end-to-end tests in [`tests/test_e2e_config.py`](tests/test_e2e_config.py):
   - Test: default config creation from empty directory
   - Test: loading bundled default-config.json passes validation
   - Test: all 13 SSH targets accessible via `get_ssh_target()`
   - Test: all 35 commands in default rules
   - Test: all 10 block patterns load as valid regex
   - Test: settings have correct defaults
   - Test: hot-reload picks up new target
   - Test: hot-reload rejects invalid config, preserves old data
   - Test: created config file has 0o600 permissions
9. Run all tests: `python -m pytest tests/ -v` and ensure the full test suite passes

---

## Self-Test Criteria

After implementing this sub-plan, the following must be true:

- [ ] `default-config.json` exists at project root with valid JSON
- [ ] `docker compose build` succeeds
- [ ] `docker compose up -d` starts the container successfully
- [ ] Health check at `http://localhost:8080/health` returns `{"status": "ok"}`
- [ ] `ssh-servers.json` has been deleted
- [ ] `compose.yaml` no longer references `ssh-servers.json`
- [ ] Dockerfile copies `default-config.json` into the image
- [ ] First startup with empty config directory creates `ssh-mcp-config.json`
- [ ] All 13 SSH targets are available via the MCP tool `ssh_list_servers`
- [ ] All e2e tests pass
- [ ] All unit tests from sub-plans 02a, 02b, 02c still pass
