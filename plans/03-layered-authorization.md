# Plan 03: Layered Authorization (Per-Client, Per-Target Permissions)

## Master Plan — contains all context needed for implementation

---

## Overview

Implement fine-grained command authorization where different clients (identified by API key and/or source IP range) can be granted different sets of allowed commands for different SSH targets. The authorization chain evaluates in a fixed order, and `block_patterns` (global) always take precedence over any allow rules.

The config schema uses a **rule-based** approach: each authorization entry (`default`, each API key, each network) contains a list of rule objects. Each rule specifies which SSH targets it applies to (`targets` field) and which commands are allowed (`commands` field).

## Authorization Chain (Evaluation Order)

```
Incoming: command="docker ps", target="knubbel", source_ip="10.42.43.78", api_key="bearer-token"
      |
      v
1. Does command match any block_pattern?
   YES → DENY (log: "blocked by pattern <pattern>")
   NO  → continue
      |
      v
2. Check DEFAULT rules: any rule where targets includes "knubbel" or "*"
   AND commands includes "docker" or "*"?
   YES → ALLOW (log: "allowed by default")
   NO  → continue
      |
      v
3. API key provided? Hash matches config entry "monitoring-service"?
   Check that entry's rules: any rule where targets includes "knubbel" or "*"
   AND commands includes "docker" or "*"?
   YES → ALLOW (log: "allowed by API key monitoring-service")
   NO  → continue
      |
      v
4. Source IP "10.42.43.78" matches network "10.42.43.0/24"?
   Check that network's rules: any rule where targets includes "knubbel" or "*"
   AND commands includes "docker" or "*"?
   YES → ALLOW (log: "allowed by network homelab-internal (10.42.43.0/24)")
   NO  → continue
      |
      v
5. DENY (log: "denied: not in any allow list for target knubbel")
```

### Key point: Target filtering

At each layer (default, API key, network), **only rules matching the requested target** are evaluated. Rules with `targets: ["other-server"]` are ignored when the request is for `"knubbel"`.

### Multiple rules per entry

An API key or network can have multiple rule objects. ALL matching rules are checked — if ANY one matches both the target and the command, access is granted.

Example:
```json
{
  "name": "admin-tool",
  "key_hash": "sha256:...",
  "rules": [
    { "targets": ["knubbel", "home"], "commands": ["docker", "systemctl"] },
    { "targets": ["*"], "commands": ["uptime", "free", "df"] }
  ]
}
```
- For target `"knubbel"`: `docker`, `systemctl`, `uptime`, `free`, `df` are all allowed
- For target `"mail"`: only `uptime`, `free`, `df` are allowed (mail doesn't match the first rule)

## Config Schema (Relevant Section from Plan 02)

```json
{
  "allowed_commands": {
    "default": [
      {
        "targets": ["*"],
        "commands": ["hostname", "uptime", "free", "df", "du", "..."]
      }
    ],
    "api_keys": [
      {
        "name": "monitoring-service",
        "key_hash": "sha256:abc123def456...",
        "rules": [
          {
            "targets": ["knubbel", "home", "hole"],
            "commands": ["docker", "docker-compose", "systemctl", "journalctl"]
          },
          {
            "targets": ["*"],
            "commands": ["uptime", "free", "df", "ping"]
          }
        ]
      },
      {
        "name": "full-admin",
        "key_hash": "sha256:111222333...",
        "rules": [
          {
            "targets": ["*"],
            "commands": ["*"]
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
      },
      {
        "name": "guest-wifi",
        "range": "10.42.99.0/24",
        "rules": [
          {
            "targets": ["piprint"],
            "commands": ["uptime", "free", "df", "ping"]
          }
        ]
      }
    ]
  }
}
```

## Client Identity Extraction

### Source IP

Extracted in middleware/request handler:
1. Check `X-Forwarded-For` header (take the leftmost IP = original client)
2. If not present, use the direct connection IP from the request socket
3. Use Python's `ipaddress` module for parsing and CIDR matching

### API Key

Extracted from HTTP header:
1. Check `Authorization: Bearer <key>` header
2. If present, compute `sha256("<key>")` and compare against `key_hash` values in config
3. Store the matched `name` for logging purposes
4. If no match found, treat as "no API key" (silently fall through to default/network layers)

## Authorization Module

**File**: [`lib/auth.py`](lib/auth.py)

### Class: `AuthorizationManager`

```python
class AuthorizationManager:
    """
    Evaluates whether a command is allowed for a given client context and target.
    Uses the layered chain: block_patterns → default → api_key → network → deny.
    At each layer, only rules matching the requested target are evaluated.
    
    Does NOT own config — receives ConfigManager reference for current data.
    """
    
    def __init__(self, config_manager: ConfigManager):
        self._config_manager = config_manager
    
    def check_command(
        self, 
        command: str, 
        target: str,
        source_ip: str | None = None, 
        api_key: str | None = None
    ) -> AuthResult:
        """
        Evaluate the command through the authorization chain.
        
        Args:
            command: The raw command string to validate
            target: SSH target ID (e.g., "knubbel")
            source_ip: Client IP address (from request)
            api_key: Raw API key from Authorization header (or None)
        
        Returns:
            AuthResult with allowed: bool, reason: str, matched_via: str
        """
        ...
    
    def list_allowed_commands(
        self, 
        target: str,
        source_ip: str | None = None, 
        api_key: str | None = None
    ) -> list[str]:
        """
        Collect all allowed commands for the given client context and target.
        
        Args:
            target: SSH target ID (mandatory)
            source_ip: Client IP address
            api_key: Raw API key
        
        Returns:
            Deduplicated, sorted list of command names (or ["*"] if full access)
        """
        ...
    
    def _check_block_patterns(self, command: str) -> str | None:
        """Returns the matching block pattern string or None."""
        ...
    
    def _match_api_key(self, api_key: str) -> dict | None:
        """Hash the key and find matching entry. Returns the entry dict or None."""
        ...
    
    def _match_network(self, source_ip: str) -> dict | None:
        """Find matching network range for the IP. Returns the entry dict or None."""
        ...
    
    def _collect_commands_for_target(
        self, rules: list[dict], target: str
    ) -> set[str]:
        """
        Given a list of rule objects, collect all commands that apply to the target.
        Returns a set of command strings. If any matching rule has commands=["*"],
        returns {"*"}.
        """
        ...
    
    def _is_command_allowed_by_rules(
        self, command: str, rules: list[dict], target: str
    ) -> bool:
        """
        Check if any rule matching 'target' allows 'command'.
        Handles base-command extraction (strip arguments) and wildcard "*".
        """
        ...
```

### Data class: `AuthResult`

```python
@dataclass
class AuthResult:
    allowed: bool
    reason: str          # human-readable reason for logging
    matched_via: str     # "default" | "api_key:<name>" | "network:<name> (<range>)" | "blocked:<pattern>" | "denied"
```

## Changes to MCP Tools in [`server.py`](server.py)

### `ssh_execute_command` — updated signature and logic

The tool now needs to extract client identity from the HTTP request context. With FastMCP (Starlette/ASGI-based), the request is accessible.

```python
@mcp.tool()
def ssh_execute_command(server_name: str, command: str, timeout: int = 30) -> str:
    """
    Execute a command on a remote SSH server.
    
    Args:
        server_name: Name of the SSH target (from ssh_list_servers)
        command: Shell command to execute (authorization-enforced)
        timeout: Command timeout in seconds (default 30, max 120)
    """
    # 1. Extract client identity from request
    source_ip = extract_client_ip(request)      # from X-Forwarded-For or socket
    api_key = extract_api_key(request)          # from Authorization: Bearer
    
    # 2. Authorization check (with target context)
    auth_result = auth_manager.check_command(
        command=command,
        target=server_name,
        source_ip=source_ip,
        api_key=api_key
    )
    
    # 3. Log the attempt
    logger.log_command_attempt(...)
    
    if not auth_result.allowed:
        return f"ERROR: Command '{command}' is not allowed. {auth_result.reason}"
    
    # 4. Execute command (existing logic)
    ...
```

### `ssh_list_allowed_commands` — NEW tool

```python
@mcp.tool()
def ssh_list_allowed_commands(server_name: str) -> str:
    """
    List all commands the current client is allowed to execute on a specific SSH target.
    Takes into account the client's API key and source IP.
    
    Args:
        server_name: Name of the SSH target to check permissions for
    """
    source_ip = extract_client_ip(request)
    api_key = extract_api_key(request)
    
    commands = auth_manager.list_allowed_commands(
        target=server_name,
        source_ip=source_ip,
        api_key=api_key
    )
    
    if "*" in commands:
        return f"All commands allowed on {server_name} (except blocked patterns)"
    
    return f"Allowed commands on {server_name}:\n" + "\n".join(sorted(commands))
```

### `ssh_list_servers` — updated

Reads from ConfigManager instead of the old `ssh-servers.json`:

```python
@mcp.tool()
def ssh_list_servers() -> str:
    """List all configured SSH servers."""
    targets = config_manager.list_ssh_targets()
    lines = []
    for target_id in targets:
        t = config_manager.get_ssh_target(target_id)
        lines.append(f"{target_id}: {t['username']}@{t['host']}:{t.get('port', 22)}")
    return "\n".join(lines) if lines else "No servers configured"
```

## Edge Cases & Decisions

| Scenario | Behavior |
|----------|----------|
| Target ID doesn't exist in `ssh_targets` | `check_command()` returns `AuthResult(allowed=False, reason="Unknown target")` — handled before auth chain |
| Command contains pipe/chain (`cmd1 \| cmd2`) | Each segment is individually validated against the SAME target and client context |
| Command contains semicolon (`cmd1; cmd2`) | Each segment is individually validated |
| `"*"` in commands of a matching rule | ALL commands pass for that layer (except block_patterns) |
| `"*"` in targets of a rule | Rule applies to all SSH targets |
| Multiple API keys with same hash | First match wins (config order) — log a warning |
| Source IP matches multiple networks | First match wins (config order) — log a warning |
| API key provided but hash doesn't match any entry | Treat as "no API key" → silently fall through |
| Source IP doesn't match any network range | Treat as "no network match" → silently fall through |
| Empty `default` rules list | Only API key or network matches can allow commands |
| A rule references a non-existent target ID | Config validation catches this at load time — rejected |
| All three layers have no matching rule for this target | DENY |

## Helper: Command Base Extraction

When checking if a command is "allowed", we extract the base command (first word) and check that against the allowed lists:

```python
def _extract_base_command(command: str) -> str:
    """Extract the base command from a command string."""
    return command.strip().split()[0] if command.strip() else ""
```

For piped/semicolon commands, each segment is individually validated:
```python
def _split_command_segments(command: str) -> list[str]:
    """Split command by pipes and semicolons for individual validation."""
    parts = re.split(r'[|&;]', command)
    return [p.strip() for p in parts if p.strip()]
```

## Files to Create/Modify

### New files

| File | Purpose |
|------|---------|
| [`lib/auth.py`](lib/auth.py) | `AuthorizationManager`, `AuthResult`, helper functions |
| [`tests/test_auth.py`](tests/test_auth.py) | Unit tests for authorization logic |

### Modified files

| File | Change |
|------|--------|
| [`server.py`](server.py) | Replace `validate_command()` with `AuthorizationManager`; extract client identity from request; add `ssh_list_allowed_commands` tool; update `ssh_list_servers` |
| [`lib/config.py`](lib/config.py) | Validation logic for rule objects, targets field, api_keys and networks sections |

## Implementation Steps

1. Create [`lib/auth.py`](lib/auth.py):
   - `AuthResult` dataclass
   - `AuthorizationManager` class with `check_command()` and `list_allowed_commands()`
   - Helper functions: `_extract_base_command()`, `_split_command_segments()`
   - IP matching using `ipaddress` module
   - API key hashing using `hashlib.sha256`

2. Write tests in [`tests/test_auth.py`](tests/test_auth.py):
   - Block pattern prevents execution regardless of allow lists
   - Default allows, chain stops (target-specific: default has rule for this target)
   - Default has no rule for this target → chain continues to API key
   - API key rule matches target → allows
   - API key rule doesn't match target (wrong target) → chain continues
   - Network rule matches target AND IP → allows
   - `"*"` wildcard in targets → rule applies to all targets
   - `"*"` wildcard in commands → all commands allowed
   - Multiple rules per API key: one matches target, one doesn't
   - Unknown API key falls through
   - Unmatched IP falls through
   - Piped commands validated individually
   - `list_allowed_commands()` returns correct union across layers for a specific target
   - `list_allowed_commands()` returns `["*"]` when wildcard present

3. Update [`server.py`](server.py):
   - Remove old `validate_command()` function
   - Add request header extraction helpers (`extract_client_ip`, `extract_api_key`)
   - Instantiate `AuthorizationManager` with `ConfigManager`
   - Update `ssh_execute_command` to use auth chain with target parameter
   - Add `ssh_list_allowed_commands` tool (mandatory `server_name` parameter)
   - Update `ssh_list_servers` to read from ConfigManager

4. Update [`lib/config.py`](lib/config.py):
   - Validation: rules must have `targets` (list of strings or `["*"]`)
   - Validation: rules must have `commands` (list of strings or `["*"]`)
   - Validation: target IDs in rules must exist in `ssh_targets` (or be `"*"`)
   - Validation: `api_keys[].rules` is a non-empty list
   - Validation: `networks[].rules` is a non-empty list
   - Validation: `default` is a non-empty list of rule objects
