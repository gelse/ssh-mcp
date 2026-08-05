# Plan 02: External Config File with Watching

## Master Plan — contains all context needed for implementation

---

## Overview

Replace the hardcoded `ALLOWED_COMMANDS` and `BLOCK_PATTERNS` lists in [`server.py`](server.py:20-41) AND the separate [`ssh-servers.json`](ssh-servers.json) file with a single unified JSON configuration file that is:
- Stored in a dedicated config directory (default: `/config`, overridable via `CONFIG_DIR` env var or CLI `--config-dir` argument)
- Auto-created with sensible defaults on first startup if missing
- Watched for changes (15-second polling interval), with hot-reload of configuration at runtime

## Current State (to be replaced)

1. **Hardcoded lists in [`server.py`](server.py:20-41)**:
```python
ALLOWED_COMMANDS = ["hostname", "uptime", ...]  # 35 commands
BLOCK_PATTERNS = [r'\brm\s+-rf\b', ...]          # 9 patterns
```

2. **Separate [`ssh-servers.json`](ssh-servers.json)** with 13 server entries (keyed by name):
```json
{
  "knubbel": {"host": "knubbel.gelse.local", "port": 22, "username": "ansible", "privateKey": "/host/data/ssh_key"},
  ...
}
```

Both are replaced by a single unified config file.

## Config File Format

**Path**: `<CONFIG_DIR>/ssh-mcp-config.json` (e.g., `/config/ssh-mcp-config.json`)

**Full Schema**:

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
    "home": {
      "host": "home.gelse.local",
      "port": 22,
      "username": "root",
      "password": "secret123"
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
        "commands": ["hostname", "uptime", "free", "df", "du",
                     "docker", "docker-compose", "systemctl", "journalctl",
                     "kubectl", "ps", "top", "htop",
                     "ls", "cat", "head", "tail", "grep", "find", "wc",
                     "ss", "netstat", "ip", "ping",
                     "curl", "wget", "pihole",
                     "echo", "date", "who", "id",
                     "sqlite3", "zpool", "zfs",
                     "lsof", "mount", "smartctl", "lsblk", "nvme", "lsscsi"]
      }
    ],
    "api_keys": [
      {
        "name": "monitoring-service",
        "key_hash": "sha256:abc123...",
        "rules": [
          {
            "targets": ["knubbel", "home", "hole"],
            "commands": ["docker", "docker-compose", "systemctl", "journalctl", "ps", "top"]
          },
          {
            "targets": ["*"],
            "commands": ["uptime", "free", "df", "ping"]
          }
        ]
      }
    ],
    "networks": [
      {
        "name": "homelab-internal",
        "range": "10.42.43.0/24",
        "rules": [
          {
            "targets": ["*"],
            "commands": ["*"]
          }
        ]
      }
    ]
  },
  "settings": {
    "max_output_length": 50000,
    "command_timeout_max": 120
  }
}
```

### Field Descriptions

#### Top-level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | int | yes | Config schema version (currently `1`) |
| `ssh_targets` | object | yes | Map of SSH target ID → connection details |
| `block_patterns` | list[string] | yes | Global regex patterns that ALWAYS block execution |
| `allowed_commands` | object | yes | Authorization rules (see below) |
| `settings` | object | yes | General server settings |

#### `ssh_targets` entries

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `<id>` (key) | string | yes | Unique identifier for the SSH target (e.g., "knubbel", "home") |
| `host` | string | yes | Hostname or IP address |
| `port` | int | no | SSH port (default: 22) |
| `username` | string | yes | SSH username |
| `private_key` | string | no | Path to private key file. Takes precedence over `password` for SSH authentication. |
| `password` | string | no | SSH password. If both `private_key` and `password` are present, `private_key` is used for the SSH connection and `password` is retained for potential `sudo` access (see Plan 05). Plaintext in config file — restrict file permissions! |

**Validation rule**: At least one of `private_key` or `password` MUST be present for each target. If neither is present, config validation fails.

**Precedence**: When both `private_key` and `password` are specified, the `private_key` is used for SSH authentication. The `password` field is preserved for `sudo -S` usage (Plan 05: sudo support).

**Migration from old `ssh-servers.json`**: The old key `privateKey` becomes `private_key` (snake_case). The old default path `/host/data/ssh_key` becomes the path specified in the config file (paths are used as-is, relative to the container filesystem). In the bundled `default-config.json`, this is `/app/ssh_key` (since the key is mounted into `/app/`).

#### `allowed_commands` — Rule structure

Each section (`default`, each `api_keys` entry, each `networks` entry) contains a list of **rule objects**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `targets` | list[string] or `["*"]` | yes | SSH target IDs this rule applies to. `["*"]` means all targets. |
| `commands` | list[string] or `["*"]` | yes | Allowed commands. `["*"]` means all commands (except block_patterns). |

**Multiple rules**: An API key or network can have multiple rule objects to specify different commands for different targets. During evaluation, all rules are checked; if ANY rule matches both the target and the command, the command is allowed.

#### `default` section

The `default` section is also a list of rule objects (same structure). This allows different default commands per target:
```json
"default": [
  { "targets": ["*"], "commands": ["hostname", "uptime", "free"] },
  { "targets": ["knubbel", "home"], "commands": ["docker", "systemctl"] }
]
```

#### `api_keys` entries

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable name for logging. Never log the actual key. |
| `key_hash` | string | yes | SHA-256 hash of the API key (`sha256:<hex>`). |
| `rules` | list[rule] | yes | List of target→commands rule objects. |

#### `networks` entries

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable name for logging. |
| `range` | string | yes | CIDR notation IP range (e.g., "10.42.43.0/24"). |
| `rules` | list[rule] | yes | List of target→commands rule objects. |

#### `settings`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `max_output_length` | int | yes | 50000 | Max bytes of command output |
| `command_timeout_max` | int | yes | 120 | Max seconds a command may run |

## Configuration Manager Module

**File**: [`lib/config.py`](lib/config.py)

### Class: `ConfigManager`

```python
class ConfigManager:
    """
    Manages unified configuration file loading, validation, default creation,
    and hot-reload via file polling.
    
    Singleton pattern — one instance per process.
    Replaces both the old hardcoded lists AND ssh-servers.json.
    """
    
    def __init__(self, config_dir: str, polling_interval: float = 15.0): ...
    
    @property
    def config_path(self) -> Path:
        """Returns Path to the actual config JSON file."""
        ...
    
    @property
    def data(self) -> dict:
        """Returns the currently loaded and validated config as a dict (thread-safe)."""
        ...
    
    def load(self) -> dict:
        """
        Load and validate config from file.
        Creates default if missing.
        Returns the loaded config dict.
        """
        ...
    
    def start_watcher(self) -> None:
        """Start the background polling thread for hot-reload."""
        ...
    
    def stop_watcher(self) -> None:
        """Stop the background polling thread gracefully."""
        ...
    
    def get_ssh_target(self, target_id: str) -> dict | None:
        """
        Convenience: return ssh_targets[target_id] or None.
        """
        ...
    
    def list_ssh_targets(self) -> list[str]:
        """
        Convenience: return list of all SSH target IDs.
        """
        ...
    
    def _ensure_default_config(self) -> None:
        """
        Copy default config to config directory if no config file exists.
        The bundled default-config.json contains the old ssh-servers.json data
        plus the old hardcoded ALLOWED_COMMANDS and BLOCK_PATTERNS.
        """
        ...
    
    def _validate(self, config: dict) -> dict:
        """
        Validate the full config structure and values.
        Raises ConfigValidationError with detailed message on failure.
        Returns normalized config dict.
        """
        ...
```

### Config File Locations

| Purpose | Path | Description |
|---------|------|-------------|
| Bundled default | `/app/default-config.json` | Shipped in the Docker image; copied to `<CONFIG_DIR>/ssh-mcp-config.json` on first startup if no config exists |
| Live config | `<CONFIG_DIR>/ssh-mcp-config.json` | The runtime configuration file, user-maintained. Default: `/config/ssh-mcp-config.json` |

### Implementation Notes

- **Regex escaping in JSON**: The `block_patterns` are stored as JSON strings, so regex metacharacters like `\b`, `\s`, `\d` must be double-escaped in the JSON file (e.g., `\\brm\\s+-rf\\b`). When loaded by Python's `json.load()`, they become single-escaped and work correctly with `re.compile()`. The bundled `default-config.json` MUST use double-escaped patterns.
- **Watcher thread**: The `start_watcher()` method spawns a `threading.Thread` with `daemon=True`. This ensures the watcher does not block process shutdown. The thread polls `os.path.getmtime()` every `polling_interval` seconds (default 15).

### Validation Rules (complete)

1. **`version`**: Positive integer
2. **`ssh_targets`**: Non-empty object. Each entry:
   - `host` is a non-empty string
   - `port` is a positive integer ≤ 65535 (or absent, defaults to 22)
   - `username` is a non-empty string
   - At least one of `private_key` or `password` is present and non-empty
   - `private_key` if present is a non-empty string (path)
   - `password` if present is a non-empty string
3. **`block_patterns`**: List of strings, each must be a compilable regex (tested with `re.compile()`)
4. **`allowed_commands.default`**: List of rule objects. Each rule:
   - `targets` is a non-empty list of strings, or exactly `["*"]`
   - `commands` is a non-empty list of strings, or exactly `["*"]`
   - Target IDs referenced in `targets` must exist in `ssh_targets` (or be `"*"`)
5. **`allowed_commands.api_keys`**: List of objects. Each:
   - `name` is a non-empty string
   - `key_hash` matches pattern `^sha256:[a-f0-9]{64}$`
   - `rules` is a non-empty list of valid rule objects
6. **`allowed_commands.networks`**: List of objects. Each:
   - `name` is a non-empty string
   - `range` is a valid CIDR string (parsable by `ipaddress.ip_network()`)
   - `rules` is a non-empty list of valid rule objects
7. **`settings`**:
   - `max_output_length` is an integer >= 1
   - `command_timeout_max` is an integer >= 1

**On validation failure during hot-reload**: The error is logged (via the logger from Plan 04), and the **previous valid config is kept**. The server continues running with the last-known-good configuration.

### Key behaviors

1. **Default config on startup**: If `<CONFIG_DIR>/ssh-mcp-config.json` does not exist, copy [`default-config.json`](default-config.json) (bundled in the package) into the config directory. This follows the standard Docker pattern.

2. **Hot-reload (polling)**:
   - Background daemon thread checks `os.path.getmtime()` of the config file every 15 seconds
   - If modification time changed since last load, reload and validate
   - If validation fails, log the error (Plan 04) and keep the previous valid config
   - Thread-safe access via `threading.Lock`

3. **Startup parameter**: Accept `--config-dir` CLI argument. Fallback chain: CLI arg → `CONFIG_DIR` env var → `/config` (default)

## Changes to [`server.py`](server.py) — SSH Client

The `get_ssh_client()` function must be updated to read SSH targets from `ConfigManager` instead of the old `ssh-servers.json`:

```python
def get_ssh_client(server_name: str, config_manager: ConfigManager):
    target = config_manager.get_ssh_target(server_name)
    if target is None:
        available = ", ".join(config_manager.list_ssh_targets())
        raise ValueError(f"Server '{server_name}' not found. Available: {available}")
    
    host = target["host"]
    port = target.get("port", 22)
    username = target["username"]
    
    # private_key takes precedence for SSH authentication
    key_path = target.get("private_key")
    password = target.get("password")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    connect_kwargs = {"hostname": host, "port": port, "username": username, "timeout": 10}
    
    if key_path:
        key_path = os.path.expanduser(key_path)
        if os.path.exists(key_path):
            try:
                key = paramiko.Ed25519Key.from_private_key_file(key_path)
            except Exception:
                try:
                    key = paramiko.RSAKey.from_private_key_file(key_path)
                except Exception:
                    key = None
            if key:
                connect_kwargs["pkey"] = key
    elif password:
        connect_kwargs["password"] = password
    
    client.connect(**connect_kwargs)
    return client
```

The old path-mangling `key_path.replace("/host/data/", str(BASE_DIR) + "/")` is removed — paths in the config file should be correct as-is.

## Files to Create/Modify

### New files

| File | Purpose |
|------|---------|
| [`lib/__init__.py`](lib/__init__.py) | Package init |
| [`lib/config.py`](lib/config.py) | `ConfigManager` class with full validation |
| [`default-config.json`](default-config.json) | Bundled default config with all current SSH targets, allowed commands, and block patterns |
| [`tests/test_config.py`](tests/test_config.py) | Unit tests for ConfigManager |

### Modified files

| File | Change |
|------|--------|
| [`server.py`](server.py) | Remove hardcoded lists; remove `load_servers()`; update `get_ssh_client()` to use ConfigManager; update `ssh_list_servers()` to read from config; add `--config-dir` CLI arg; start config watcher |
| [`Dockerfile`](Dockerfile) | Add `default-config.json` to image |
| [`compose.yaml`](compose.yaml) | Add `CONFIG_DIR` env var; mount `./config:/config`; remove mount of `ssh-servers.json` (no longer needed) |

### Removed files

| File | Reason |
|------|--------|
| [`ssh-servers.json`](ssh-servers.json) | Replaced by `ssh_targets` section in unified config |

## Migration Path from Old `ssh-servers.json`

The bundled `default-config.json` will include all 13 current SSH targets with:
- `privateKey` → `private_key`
- `/host/data/ssh_key` → `/app/ssh_key` (new mount path from Plan 01)
- Passwords preserved as-is (e.g., solaxpi's `"tabasco"`)

## Implementation Steps

1. Create `lib/` package with `__init__.py`
2. Create `default-config.json` with all current data migrated to the new schema
3. Create [`lib/config.py`](lib/config.py) with `ConfigManager` class
4. Write tests in [`tests/test_config.py`](tests/test_config.py):
   - Test loading valid config
   - Test default config creation when file missing
   - Test validation: missing required fields
   - Test validation: ssh_target missing both key and password
   - Test validation: invalid CIDR in network range
   - Test validation: invalid regex in block_patterns
   - Test validation: target ID in rules referencing non-existent ssh_target
   - Test validation: invalid key_hash format
   - Test hot-reload detection (mocked mtime changes)
   - Test hot-reload with invalid config → keeps old config
   - Test thread safety
5. Update [`server.py`](server.py):
   - Add argparse for `--config-dir`
   - Initialize ConfigManager
   - Start config watcher
   - Replace `load_servers()` with `config_manager.get_ssh_target()`
   - Update `get_ssh_client()` for new target dict structure
   - Update `ssh_list_servers()` to use `config_manager.list_ssh_targets()`
6. Update [`Dockerfile`](Dockerfile) to include `default-config.json` and `lib/`
7. Update [`compose.yaml`](compose.yaml) with volume mount and env var, remove `ssh-servers.json` mount
8. Remove [`ssh-servers.json`](ssh-servers.json)
