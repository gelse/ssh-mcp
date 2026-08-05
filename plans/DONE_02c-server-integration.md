# Plan 02c: Server Integration — Wire ConfigManager into server.py

## Parent: [Plan 02 — External Config File with Watching](plans/02-config-file.md)
## Dependencies: [Plan 02a — ConfigManager Core](plans/02a-config-core.md), [Plan 02b — Hot-Reload Watcher](plans/02b-hot-reload.md)

---

## Scope

This sub-plan modifies [`server.py`](server.py) to:
- Remove the hardcoded `ALLOWED_COMMANDS` and `BLOCK_PATTERNS` lists
- Remove the old `load_servers()` function (reads [`ssh-servers.json`](ssh-servers.json))
- Add `--config-dir` CLI argument (with `CONFIG_DIR` env var fallback)
- Initialize `ConfigManager` at startup
- Start the config watcher
- Update `get_ssh_client()` to read SSH targets from `ConfigManager`
- Update `ssh_list_servers()` to read from `ConfigManager`
- Update authorization checks to use config data instead of hardcoded lists

**Requires**: `ConfigManager` with `load()`, `reload()`, `start_watcher()`, `stop_watcher()`, `get_ssh_target()`, `list_ssh_targets()`, and `data` property from Plans 02a and 02b.

**Out of scope**: Dockerfile/compose changes (→ Plan 02d), removing ssh-servers.json (→ Plan 02d).

---

## Current State in [`server.py`](server.py)

### Lines to Remove

1. **Hardcoded lists** (lines 22–43):
   - `ALLOWED_COMMANDS = [...]` (35 commands)
   - `BLOCK_PATTERNS = [...]` (9 patterns)

2. **Hardcoded constants that move to config** (lines 17–20):
   - `SERVERS_FILE = BASE_DIR / "ssh-servers.json"` — replaced by ConfigManager
   - `MAX_OUTPUT_LEN = 50000` — replaced by `config.settings.max_output_length`

3. **`load_servers()` function** — reads `ssh-servers.json`; replaced by `config_manager.get_ssh_target()`

4. **Path-mangling in `get_ssh_client()`**: `key_path.replace("/host/data/", str(BASE_DIR) + "/")` — removed

### Lines to Keep (unchanged)

- `FastMCP` setup, tool decorators (`@mcp.tool()`), `ssh_execute_command()`, `execute_command_impl()`, `is_command_allowed()`, `check_block_patterns()`
- The actual MCP tool logic — only the data sources change

---

## Changes to [`server.py`](server.py)

### 1. Add imports

```python
import argparse
from lib.config import ConfigManager, ConfigValidationError
```

### 2. Config directory resolution (add near top, after imports)

```python
def resolve_config_dir() -> str:
    """
    Resolve config directory from CLI args or environment.
    
    Priority: --config-dir CLI arg > CONFIG_DIR env var > /config (default)
    """
    parser = argparse.ArgumentParser(add_help=False)  # Don't add --help yet
    parser.add_argument("--config-dir", type=str, default=None)
    args, _ = parser.parse_known_args()  # parse_known_args to not interfere with uvicorn args
    
    if args.config_dir:
        return args.config_dir
    return os.environ.get("CONFIG_DIR", "/config")
```

### 3. Initialize ConfigManager (replace lines 17–43)

```python
BASE_DIR = Path(__file__).parent

# Config directory resolution
CONFIG_DIR = resolve_config_dir()

# Initialize configuration manager
config_manager = ConfigManager(CONFIG_DIR)

# Start hot-reload watcher (15-second polling)
config_manager.start_watcher(polling_interval=15.0)
```

**Remove**: `SERVERS_FILE`, `SSH_KEY_FILE`, `MAX_OUTPUT_LEN`, `ALLOWED_COMMANDS`, `BLOCK_PATTERNS`

### 4. Update `get_ssh_client()` (replace existing)

```python
def get_ssh_client(server_name: str):
    """
    Create and return an SSH client connected to the named server.
    Reads connection details from ConfigManager.
    """
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
    
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 10,
    }
    
    if key_path:
        key_path = os.path.expanduser(key_path)
        if os.path.exists(key_path):
            # Try Ed25519 first, then RSA
            key = None
            for key_class in (paramiko.Ed25519Key, paramiko.RSAKey):
                try:
                    key = key_class.from_private_key_file(key_path)
                    break
                except Exception:
                    continue
            if key:
                connect_kwargs["pkey"] = key
    elif password:
        connect_kwargs["password"] = password
    
    client.connect(**connect_kwargs)
    return client
```

### 5. Update `ssh_list_servers()` (replace existing)

```python
@mcp.tool()
def ssh_list_servers() -> str:
    """
    List all available SSH target servers.
    Returns JSON with server IDs and their connection details (without secrets).
    """
    targets = config_manager.list_ssh_targets()
    result = {}
    for tid in targets:
        t = config_manager.get_ssh_target(tid)
        result[tid] = {
            "host": t["host"],
            "port": t.get("port", 22),
            "username": t["username"],
        }
    return json.dumps(result, indent=2)
```

### 6. Update authorization functions

`is_command_allowed()` and `check_block_patterns()` must read from `config_manager.data` instead of module-level constants:

```python
def check_block_patterns(command: str) -> bool:
    """
    Check if the command matches any block pattern.
    Returns True if command is BLOCKED, False if it passes.
    Reads patterns from live config (supports hot-reload).
    """
    patterns = config_manager.data.get("block_patterns", [])
    for pattern in patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


def is_command_allowed(server_name: str, command: str) -> bool:
    """
    Check if the command is allowed for the given server.
    Reads rules from live config (supports hot-reload).
    
    For now, only checks the 'default' section.
    API key and network rules will be handled in Plan 03.
    """
    allowed = config_manager.data.get("allowed_commands", {})
    default_rules = allowed.get("default", [])
    
    base_cmd = command.strip().split()[0] if command.strip() else ""
    
    for rule in default_rules:
        targets = rule.get("targets", [])
        commands = rule.get("commands", [])
        
        # Check if this rule applies to the given server
        target_match = "*" in targets or server_name in targets
        if not target_match:
            continue
        
        # Check if the command is allowed
        if "*" in commands or base_cmd in commands:
            return True
    
    return False
```

### 7. Update `MAX_OUTPUT_LEN` references

Anywhere `MAX_OUTPUT_LEN` was used, replace with:
```python
config_manager.data.get("settings", {}).get("max_output_length", 50000)
```

### 8. Add atexit handler for clean shutdown (near bottom, before `mcp.run()`)

```python
import atexit

def shutdown():
    config_manager.stop_watcher()

atexit.register(shutdown)
```

### 9. Add `--config-dir` to the server's argument parser

If FastMCP's `mcp.run()` uses its own argument parsing, ensure `--config-dir` is consumed before FastMCP sees it. This is handled by `parse_known_args()` in `resolve_config_dir()`.

Verify that `mcp.run()` still works with `parse_known_args()` having consumed `--config-dir`. FastMCP uses uvicorn under the hood, which accepts its own args. The remaining unknown args (anything not `--config-dir`) are passed through to uvicorn/FastMCP.

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| [`server.py`](server.py) | **Modify** | Remove hardcoded lists, integrate ConfigManager, update all tool functions |
| [`tests/test_server.py`](tests/test_server.py) | **Create** | Integration tests for server with ConfigManager |

---

## Implementation Steps

1. Add `import argparse` and `from lib.config import ConfigManager, ConfigValidationError` to [`server.py`](server.py)
2. Add `resolve_config_dir()` function
3. Remove hardcoded `ALLOWED_COMMANDS`, `BLOCK_PATTERNS`, `SERVERS_FILE`, `MAX_OUTPUT_LEN`
4. Replace with `config_manager = ConfigManager(CONFIG_DIR)` and `config_manager.start_watcher()`
5. Rewrite `get_ssh_client()` to use `config_manager.get_ssh_target()`
6. Rewrite `ssh_list_servers()` to use `config_manager.list_ssh_targets()`
7. Update `is_command_allowed()` to read from config data
8. Update `check_block_patterns()` to read from config data
9. Replace all `MAX_OUTPUT_LEN` references with config data lookup
10. Add `atexit.register(shutdown)` for clean watcher stop
11. Create [`tests/test_server.py`](tests/test_server.py):
    - Test: `resolve_config_dir()` returns `/config` when no env var or CLI arg
    - Test: `resolve_config_dir()` respects `CONFIG_DIR` env var
    - Test: `resolve_config_dir()` respects `--config-dir` CLI arg
    - Test: `ssh_list_servers()` returns target IDs from config
    - Test: `check_block_patterns()` blocks matching commands
    - Test: `check_block_patterns()` allows non-matching commands
    - Test: `is_command_allowed()` allows commands in the default rules
    - Test: `is_command_allowed()` denies commands not in any rule
    - Test: `get_ssh_client()` raises ValueError for unknown server
    - Test: `get_ssh_client()` returns valid target info for known server (mock paramiko)
12. Run tests: `python -m pytest tests/test_server.py -v`

---

## Self-Test Criteria

After implementing this sub-plan, the following must be true:

- [ ] `python server.py --help` shows `--config-dir` option (and server starts)
- [ ] Server starts with `CONFIG_DIR` env var set to a test config directory
- [ ] Server starts with default `/config` when no env var or CLI arg
- [ ] `ssh_list_servers()` returns the correct list of SSH targets from the config
- [ ] Command authorization uses config data, not hardcoded lists
- [ ] Block pattern checking uses config data, not hardcoded lists
- [ ] Modifying the config file triggers hot-reload and affects subsequent tool calls
- [ ] Server shuts down cleanly (watcher thread stops) on `SIGTERM` / `atexit`
- [ ] All integration tests pass
