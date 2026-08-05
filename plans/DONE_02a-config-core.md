# Plan 02a: ConfigManager Core — Loading, Validation & Default Creation

## Parent: [Plan 02 — External Config File with Watching](plans/02-config-file.md)

---

## Scope

This sub-plan covers only the **core `ConfigManager` class** in [`lib/config.py`](lib/config.py):
- Config directory resolution (`--config-dir` CLI arg → `CONFIG_DIR` env var → `/config`)
- Loading and parsing the JSON config file
- Full validation of the config schema
- Default config creation (copy [`default-config.json`](default-config.json) to config dir on first startup)

**Out of scope**: Hot-reload watching (→ Plan 02b), server.py integration (→ Plan 02c), migration/cleanup (→ Plan 02d).

---

## Config File Schema

**Path**: `<CONFIG_DIR>/ssh-mcp-config.json`

```json
{
  "version": 1,
  "ssh_targets": {
    "<id>": {
      "host": "<hostname>",
      "port": 22,
      "username": "<user>",
      "private_key": "<path>",
      "password": "<password>"
    }
  },
  "block_patterns": ["\\brm\\s+-rf\\b", "..."],
  "allowed_commands": {
    "default": [
      { "targets": ["*"], "commands": ["hostname", "uptime", "..."] }
    ],
    "api_keys": [
      {
        "name": "monitoring-service",
        "key_hash": "sha256:<64-hex-chars>",
        "rules": [
          { "targets": ["knubbel"], "commands": ["docker", "ps"] }
        ]
      }
    ],
    "networks": [
      {
        "name": "homelab-internal",
        "range": "10.42.43.0/24",
        "rules": [
          { "targets": ["*"], "commands": ["*"] }
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

### JSON Escaping Note

Regex patterns in `block_patterns` must be **double-escaped** in JSON (e.g., `\\brm\\s+-rf\\b`). Python's `json.load()` decodes these to single-escaped strings suitable for `re.compile()`.

---

## Implementation: [`lib/config.py`](lib/config.py)

### Class: `ConfigManager`

```python
class ConfigManager:
    """
    Manages unified configuration file loading, validation, and default creation.
    
    Thread-safe read access via threading.Lock.
    Does NOT handle watching/polling — that's Plan 02b.
    """
    
    def __init__(self, config_dir: str):
        self._config_dir = Path(config_dir)
        self._config_path = self._config_dir / "ssh-mcp-config.json"
        self._lock = threading.Lock()
        self._data: dict = {}
        self.load()  # Load on init
    
    @property
    def config_path(self) -> Path:
        return self._config_path
    
    @property
    def data(self) -> dict:
        with self._lock:
            return self._data.copy()  # Return shallow copy for safety
    
    def load(self) -> dict:
        """
        Load and validate config from file.
        Creates default if missing.
        Returns the loaded config dict (also stored internally).
        """
        ...
    
    def reload(self) -> bool:
        """
        Re-read config file, validate, and swap if valid.
        Returns True if config changed, False otherwise.
        Keeps old config on validation failure.
        Called by the watcher (Plan 02b) and can be triggered manually.
        """
        ...
    
    def get_ssh_target(self, target_id: str) -> dict | None:
        """Return ssh_targets[target_id] or None."""
        ...
    
    def list_ssh_targets(self) -> list[str]:
        """Return list of all SSH target IDs."""
        ...
    
    def _ensure_default_config(self) -> None:
        """
        Copy default-config.json to config directory if no config file exists.
        The bundled default-config.json lives at Path(__file__).parent.parent / "default-config.json"
        (relative to lib/config.py, two levels up to project root).
        """
        ...
    
    def _validate(self, config: dict) -> dict:
        """
        Validate the full config structure and values.
        Raises ConfigValidationError with detailed message on failure.
        Returns normalized config dict (with defaults applied).
        """
        ...
```

### `ConfigValidationError`

```python
class ConfigValidationError(Exception):
    """Raised when config validation fails. Contains a human-readable message."""
    def __init__(self, message: str, field: str | None = None):
        self.message = message
        self.field = field  # Which field failed, e.g. "ssh_targets.knubbel.host"
        super().__init__(message)
```

### Constructor — Config Directory Resolution

The `config_dir` parameter is resolved **before** constructing `ConfigManager`. Resolution logic lives in `server.py` (Plan 02c). `ConfigManager.__init__` receives the already-resolved path.

---

### Validation Rules (complete)

1. **`version`** — Must be a positive integer. Currently only version `1` is supported.

2. **`ssh_targets`** — Must be a non-empty object. For each entry:
   - `host` — non-empty string
   - `port` — if present, positive integer ≤ 65535. If absent, defaults to 22 (applied during normalization).
   - `username` — non-empty string
   - **At least one** of `private_key` or `password` must be present and non-empty
   - `private_key` — if present, non-empty string (a path — existence is NOT checked at validation time)
   - `password` — if present, non-empty string
   - No unknown keys are allowed per target

3. **`block_patterns`** — Must be a list of strings. Each string must be a compilable regex (test with `re.compile()`).

4. **`allowed_commands`** — Must be an object with up to three keys: `default`, `api_keys`, `networks`.
   - **`default`** — Required. Must be a non-empty list of rule objects.
   - **`api_keys`** — Optional. If present, must be a list (can be empty).
   - **`networks`** — Optional. If present, must be a list (can be empty).

   **Rule object structure** (used by `default`, each `api_keys[].rules`, each `networks[].rules`):
   - `targets` — Required. Must be a non-empty list of strings, or exactly `["*"]`. Each non-`*` target must exist in `ssh_targets`.
   - `commands` — Required. Must be a non-empty list of strings, or exactly `["*"]`.

5. **`allowed_commands.api_keys`** entries:
   - `name` — Required. Non-empty string.
   - `key_hash` — Required. Must match pattern `^sha256:[a-f0-9]{64}$`.
   - `rules` — Required. Non-empty list of valid rule objects.

6. **`allowed_commands.networks`** entries:
   - `name` — Required. Non-empty string.
   - `range` — Required. Must be a valid CIDR string parsable by `ipaddress.ip_network()`.
   - `rules` — Required. Non-empty list of valid rule objects.

7. **`settings`** — Required object:
   - `max_output_length` — Required. Integer ≥ 1.
   - `command_timeout_max` — Required. Integer ≥ 1.
   - No unknown keys allowed.

8. **No unknown top-level keys** are allowed beyond: `version`, `ssh_targets`, `block_patterns`, `allowed_commands`, `settings`.

### Normalization (applied during `_validate`)

- `port` defaults to 22 if absent
- `settings.max_output_length` defaults to 50000 if absent (though required by schema)
- `settings.command_timeout_max` defaults to 120 if absent (though required by schema)

---

### `load()` Flow

```
load():
  1. Check if config file exists at self._config_path
     - If NO:
       a. Call _ensure_default_config()
       b. Now config file must exist (raise error if default creation failed)
  2. Read and parse JSON
  3. Call _validate(parsed)
  4. Acquire lock, store validated config in self._data
  5. Return validated config
```

### `reload()` Flow

```
reload():
  1. Read and parse JSON from file
  2. Call _validate(parsed)
  3. If validation succeeds:
     a. Acquire lock
     b. Store new config in self._data
     c. Return True
  4. If validation fails:
     a. Log the error (via logger, Plan 04)
     b. Keep existing self._data unchanged
     c. Return False
```

---

### `_ensure_default_config()` Flow

```
_ensure_default_config():
  1. Determine source path: Path(__file__).parent.parent / "default-config.json"
  2. If source doesn't exist → raise FileNotFoundError with clear message
  3. Create config directory if it doesn't exist: self._config_dir.mkdir(parents=True, exist_ok=True)
  4. Copy source to self._config_path using shutil.copy2()
  5. Set file permissions to 0o600 (owner read/write only — contains passwords)
  6. Log "Created default config at <path>"
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| [`lib/config.py`](lib/config.py) | **Create** | `ConfigManager` class with `ConfigValidationError`, full validation, default creation |
| [`tests/__init__.py`](tests/__init__.py) | **Create** | Test package init |
| [`tests/test_config.py`](tests/test_config.py) | **Create** | Unit tests for ConfigManager core |

### Already exists, no changes:
- [`lib/__init__.py`](lib/__init__.py) — Already present, no changes needed in this sub-plan.

---

## Implementation Steps

1. Create [`tests/__init__.py`](tests/__init__.py) (empty package init)
2. Create [`lib/config.py`](lib/config.py):
   - Define `ConfigValidationError`
   - Implement `ConfigManager.__init__` with directory setup
   - Implement `_ensure_default_config()` — copy from bundled default
   - Implement `_validate()` — all 8 validation rule groups
   - Implement `load()` — parse + validate + store
   - Implement `reload()` — re-parse + validate + swap or keep
   - Implement `data` property (thread-safe read)
   - Implement `get_ssh_target()` and `list_ssh_targets()` convenience methods
3. Create a minimal [`default-config.json`](default-config.json) with the 13 existing SSH targets, current allowed commands, and block patterns (used by `_ensure_default_config` and validated by tests)
4. Write tests in [`tests/test_config.py`](tests/test_config.py):
   - Test: loading a valid config file returns correct data
   - Test: default config creation when file is missing (uses bundled `default-config.json`)
   - Test: `get_ssh_target()` returns correct target dict
   - Test: `get_ssh_target()` returns None for non-existent target
   - Test: `list_ssh_targets()` returns all target IDs
   - Test: validation fails on missing `version`
   - Test: validation fails on empty `ssh_targets`
   - Test: validation fails when target has neither `private_key` nor `password`
   - Test: validation fails on invalid `port` (negative, zero, >65535, non-integer)
   - Test: validation fails on invalid CIDR in `networks[].range`
   - Test: validation fails on invalid regex in `block_patterns`
   - Test: validation fails on invalid `key_hash` format
   - Test: validation fails when `targets` references non-existent SSH target
   - Test: validation fails on unknown top-level key
   - Test: validation fails on unknown key inside ssh_target
   - Test: `port` defaults to 22 when absent (normalization)
   - Test: `reload()` with valid config → data updated
   - Test: `reload()` with invalid config → old data preserved, returns False
   - Test: thread safety of `data` property (multiple readers)
5. Run tests with `python -m pytest tests/test_config.py -v` and ensure all pass

---

## Self-Test Criteria

After implementing this sub-plan, the following must be true:

- [ ] `python -c "from lib.config import ConfigManager, ConfigValidationError"` succeeds
- [ ] Creating a `ConfigManager` with a directory containing no config file automatically creates a valid `default-config.json`
- [ ] Loading a valid config file returns the expected data structure
- [ ] All validation rules reject invalid configs with descriptive `ConfigValidationError` messages
- [ ] `reload()` with a valid modified config updates `data`
- [ ] `reload()` with an invalid config preserves the previous valid data and returns `False`
- [ ] All unit tests in [`tests/test_config.py`](tests/test_config.py) pass
