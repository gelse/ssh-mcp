# Plan 03a: Core Authorization Module (`lib/auth.py`)

## Prerequisite
Plan 02 (ConfigManager with `allowed_commands`, `block_patterns`, `_validate_rules`) is complete and deployed.

## Subtask
Create a new file [`lib/auth.py`](lib/auth.py) containing the `AuthorizationManager` class, `AuthResult` dataclass, and static helper functions for command extraction and segmentation. This module does **not** touch `server.py` — it is purely the authorization engine, testable in isolation using a `ConfigManager` instance.

## Files to Create

| File | Purpose |
|------|---------|
| [`lib/auth.py`](lib/auth.py) | `AuthResult`, `AuthorizationManager`, `_extract_base_command()`, `_split_command_segments()` |

## Files to Modify

*None.* This subtask is purely additive.

---

## 1. `AuthResult` Dataclass

Create at the top of [`lib/auth.py`](lib/auth.py):

```python
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AuthResult:
    allowed: bool
    reason: str          # human-readable, e.g. "allowed by default"
    matched_via: str     # "default" | "api_key:<name>" | "network:<name> (<range>)" | "blocked:<pattern>" | "denied"
```

---

## 2. Static Helper Functions

### `_extract_base_command(command: str) -> str`

```python
def _extract_base_command(command: str) -> str:
    """Extract the base command (first word) from a command string."""
    return command.strip().split()[0] if command.strip() else ""
```

### `_split_command_segments(command: str) -> list[str]`

Splits a command string by pipe (`|`), ampersand (`&`), and semicolon (`;`) for individual validation of chained/piped commands:

```python
def _split_command_segments(command: str) -> list[str]:
    """Split command by pipes and semicolons for individual validation."""
    parts = re.split(r'[|&;]', command)
    return [p.strip() for p in parts if p.strip()]
```

**Important edge case**: If the command contains zero segments (e.g., just `" "`), return an empty list. If there's exactly one segment (no pipes/semicolons), return a list with that single segment.

---

## 3. `AuthorizationManager` Class

### Constructor

```python
class AuthorizationManager:
    """
    Evaluates whether a command is allowed for a given client context and target.
    Uses the layered chain: block_patterns -> default -> api_key -> network -> deny.
    At each layer, only rules matching the requested target are evaluated.

    Does NOT own config -- receives ConfigManager reference for current data.
    """

    def __init__(self, config_manager):
        """
        Args:
            config_manager: Instance of lib.config.ConfigManager.
                            The manager reads live config via config_manager.data.
        """
        self._config_manager = config_manager
```

### `check_command(command, target, source_ip, api_key) -> AuthResult`

The core authorization method. Evaluation chain:

1. **Validate target exists**: If `target` is not in `config_manager.data["ssh_targets"]`, return `AuthResult(False, "Unknown target '<target>'", "denied")`.
2. **Check block_patterns**: Iterate `config_manager.data["block_patterns"]`. For each pattern, `re.search(pattern, command, re.IGNORECASE)`. If match → return `AuthResult(False, "blocked by pattern '<pattern>'", "blocked:<pattern>")`.
3. **Check piped/chained commands**: Call `_split_command_segments(command)`. If more than 1 segment:
   - For each segment, recursively call `check_command()` against the same `target`, `source_ip`, `api_key` — BUT skip the target-existence check (step 1) and block_patterns check (step 2) for segments to avoid double-checking.
   - If any segment is denied → return that denial `AuthResult` immediately.
   - If all segments pass → **continue** to step 4 (default rules check) with the **original** command string. The segments are individually validated for safety, but the final allow/deny decision comes from the normal layer chain applied to the original command.
   - **Rationale**: A command like `hostname | curl example.com` has `curl` blocked as a segment, so it fails at segment validation. But `hostname | grep x` passes segment validation, then proceeds to default rules where `hostname` would match. The original command is what gets logged/recorded.
4. **Check DEFAULT rules**: Get `config_manager.data["allowed_commands"]["default"]` (list of rule dicts with `targets` and `commands`). Call `_is_command_allowed_by_rules(command, default_rules, target)`. If `True` → `AuthResult(True, "allowed by default", "default")`.
5. **Check API key**: If `api_key` is not None and not empty string: hash it with `hashlib.sha256(api_key.encode()).hexdigest()`, prefix with `"sha256:"`. Compare against each entry in `config_manager.data["allowed_commands"]["api_keys"]` by `key_hash`. On match: call `_is_command_allowed_by_rules(command, entry["rules"], target)`. If `True` → `AuthResult(True, "allowed by API key <name>", "api_key:<name>")`. If hash doesn't match any entry → fall through silently.
6. **Check network**: If `source_ip` is not None and not empty string: parse with `ipaddress.ip_address(source_ip)`. For each entry in `config_manager.data["allowed_commands"]["networks"]`, check if the IP is in `ipaddress.ip_network(entry["range"], strict=False)`. On match: call `_is_command_allowed_by_rules(command, entry["rules"], target)`. If `True` → `AuthResult(True, "allowed by network <name> (<range>)", "network:<name> (<range>)")`. If IP doesn't match any network → fall through silently.
7. **Deny**: `AuthResult(False, "denied: not in any allow list for target <target>", "denied")`.

### `list_allowed_commands(target, source_ip, api_key) -> list[str]`

Collect and return a sorted, deduplicated list of all command base names allowed for this client context and target:

1. If target doesn't exist → return `[]`.
2. Initialize an empty set `commands`.
3. For the **default** layer: call `_collect_commands_for_target(default_rules, target)`. Union into `commands`. If `"*"` is in the result, return `["*"]` immediately.
4. If `api_key` is provided and matches an entry: call `_collect_commands_for_target(entry["rules"], target)`. Union into `commands`. If `"*"` in result → return `["*"]`.
5. If `source_ip` matches a network entry: call `_collect_commands_for_target(entry["rules"], target)`. Union into `commands`. If `"*"` in result → return `["*"]`.
6. Return `sorted(commands)`.

**Note**: `list_allowed_commands` does NOT check `block_patterns`. It only returns what the allow rules permit. The caller (tool) is responsible for communicating that block patterns may further restrict commands.

### `_is_command_allowed_by_rules(self, command, rules, target) -> bool`

Private method, used by both `check_command` and the piped-command recursion:

```python
def _is_command_allowed_by_rules(self, command: str, rules: list[dict], target: str) -> bool:
    """
    Check if any rule matching 'target' allows 'command'.
    Handles base-command extraction and wildcard "*".
    """
    base_cmd = _extract_base_command(command)
    if not base_cmd:
        return False

    for rule in rules:
        targets = rule.get("targets", [])
        commands = rule.get("commands", [])

        # Check if this rule applies to the given target
        target_match = "*" in targets or target in targets
        if not target_match:
            continue

        # Check if the command is allowed
        if "*" in commands or base_cmd in commands:
            return True

    return False
```

### `_collect_commands_for_target(self, rules, target) -> set[str]`

Private method, used by `list_allowed_commands`:

```python
def _collect_commands_for_target(self, rules: list[dict], target: str) -> set[str]:
    """
    Given a list of rule objects, collect all commands that apply to the target.
    Returns a set of command strings. If any matching rule has commands=["*"],
    returns {"*"}.
    """
    result = set()
    for rule in rules:
        targets = rule.get("targets", [])
        commands = rule.get("commands", [])

        # Check target match
        if "*" not in targets and target not in targets:
            continue

        if "*" in commands:
            return {"*"}

        result.update(commands)
    return result
```

### Logging

Use `logger.debug(...)` for each layer traversal decision (e.g., "checking default rules for target knubbel", "no default rule matched for docker on knubbel", "API key matched: monitoring-service", etc.). Use `logger.info(...)` for the final allow/deny decision.

---

## 4. Dependencies

- `hashlib` (stdlib)
- `ipaddress` (stdlib)
- `re` (stdlib)
- `logging` (stdlib)
- `dataclasses` (stdlib)
- `lib.config.ConfigManager` — the existing class, accessed only via the reference passed to `__init__`

---

## 5. Design Decisions (from Plan 03)

| Scenario | Behavior |
|----------|----------|
| Target ID doesn't exist in `ssh_targets` | `check_command()` returns `AuthResult(allowed=False, reason="Unknown target '<target>'", matched_via="denied")` |
| Command contains pipe/chain (`cmd1 \| cmd2`) | Each segment individually validated against the SAME target and client context; ALL must pass |
| Command contains semicolon (`cmd1; cmd2`) | Same as pipe — each segment individually validated |
| `"*"` in commands of a matching rule | ALL commands pass for that layer (except block_patterns) |
| `"*"` in targets of a rule | Rule applies to all SSH targets |
| API key provided but hash doesn't match | Treat as "no API key" → silently fall through |
| Source IP doesn't match any network | Treat as "no network match" → silently fall through |
| Empty `default` rules list | Config validation already rejects this; not a runtime concern |
| All three layers have no matching rule | `AuthResult(False, "denied: not in any allow list for target <target>", "denied")` |

---

## 6. Compatibility with Existing Code

The `ConfigManager` already exposes:
- `config_manager.data` → read the full validated config (shallow copy, thread-safe)
- `config_manager.data.get("block_patterns", [])` → list of regex strings
- `config_manager.data.get("allowed_commands", {})` → dict with `default`, `api_keys`, `networks`
- `config_manager.data.get("ssh_targets", {})` → dict of target definitions

The `AuthorizationManager` reads from this structure at call time — it gets the live data on each `check_command()` call, which means hot-reload is transparently supported.

---

## 7. What This Subtask Does NOT Do

- Does NOT modify [`server.py`](server.py)
- Does NOT modify [`lib/config.py`](lib/config.py) (validation is already complete from Plan 02)
- Does NOT add request header extraction (that's in 03c)
- Does NOT add the `ssh_list_allowed_commands` MCP tool (that's in 03d)
- Does NOT log to a file — pure in-memory authorization logic

---

## 8. Acceptance Criteria (Verifiable)

1. `AuthResult` can be imported and instantiated with `(allowed=True/False, reason="...", matched_via="...")`
2. `_extract_base_command("docker ps -a")` returns `"docker"`
3. `_extract_base_command("   uptime   ")` returns `"uptime"`
4. `_extract_base_command("")` returns `""`
5. `_split_command_segments("ls | grep foo")` returns `["ls", "grep foo"]`
6. `_split_command_segments("echo hi; uptime")` returns `["echo hi", "uptime"]`
7. `_split_command_segments("hostname")` returns `["hostname"]`
8. `AuthorizationManager` can be instantiated with a `ConfigManager` reference
9. `check_command("docker ps", "knubbel")` evaluates through the chain and returns an `AuthResult`
10. `list_allowed_commands("knubbel")` returns a sorted list of allowed command base names
