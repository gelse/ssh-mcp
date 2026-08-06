# Plan 03b: Unit Tests for AuthorizationManager

## Prerequisite
Plan 03a (`lib/auth.py`) must be implemented first because these tests import `AuthorizationManager` and `AuthResult`.

## Subtask
Create [`tests/test_auth.py`](tests/test_auth.py) containing comprehensive unit tests for the `AuthorizationManager` class, `AuthResult`, and helper functions. These tests use `ConfigManager` with temporary directories and in-memory configs — no SSH, no HTTP, no Docker needed.

## Files to Create

| File | Purpose |
|------|---------|
| [`tests/test_auth.py`](tests/test_auth.py) | Unit tests for all authorization logic |

## Files to Modify

*None.*

---

## Test Structure

All tests follow the pattern used in [`tests/test_config.py`](tests/test_config.py):
- Use `tempfile.TemporaryDirectory()` for config files
- Write config dicts as JSON via helper functions
- Create `ConfigManager` pointing to the temp directory
- Create `AuthorizationManager(config_manager)` and call methods
- Assert on `AuthResult` fields

### Helpers (copy pattern from `tests/test_config.py`)

```python
import json
import tempfile
from pathlib import Path

from lib.config import ConfigManager
from lib.auth import AuthorizationManager, AuthResult, _extract_base_command, _split_command_segments


def _write_config(tmpdir: str, config_dict: dict) -> str:
    conf_path = Path(tmpdir) / "ssh-mcp-config.json"
    conf_path.write_text(json.dumps(config_dict), encoding="utf-8")
    return str(conf_path)


def _minimal_auth_config(**overrides) -> dict:
    """Return a minimal valid config for auth testing."""
    cfg = {
        "version": 1,
        "ssh_targets": {
            "knubbel": {"host": "10.0.0.1", "username": "admin", "password": "pw"},
            "home": {"host": "10.0.0.2", "username": "root", "password": "pw"},
            "mail": {"host": "10.0.0.3", "username": "root", "password": "pw"},
        },
        "block_patterns": [r"\brm\s+-rf\b", r"\bshutdown\b"],
        "allowed_commands": {
            "default": [
                {"targets": ["*"], "commands": ["hostname", "uptime", "free", "df", "grep"]},
            ],
            "api_keys": [
                {
                    "name": "monitoring-service",
                    "key_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # sha256("test")
                    "rules": [
                        {"targets": ["knubbel", "home"], "commands": ["docker", "systemctl", "journalctl"]},
                        {"targets": ["*"], "commands": ["uptime", "free", "df", "ping"]},
                    ],
                },
                {
                    "name": "full-admin",
                    "key_hash": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",  # sha256("foo")
                    "rules": [
                        {"targets": ["*"], "commands": ["*"]},
                    ],
                },
            ],
            "networks": [
                {
                    "name": "homelab-internal",
                    "range": "10.42.43.0/24",
                    "rules": [
                        {"targets": ["*"], "commands": ["*"]},
                    ],
                },
                {
                    "name": "guest-wifi",
                    "range": "10.42.99.0/24",
                    "rules": [
                        {"targets": ["piprint"], "commands": ["uptime", "free", "ping"]},
                    ],
                },
            ],
        },
        "settings": {"max_output_length": 50000, "command_timeout_max": 120},
    }
    cfg.update(overrides)
    return cfg


def _make_auth_manager(tmp_path: Path, config: dict = None):
    """Create ConfigManager + AuthorizationManager from given config."""
    if config is None:
        config = _minimal_auth_config()
    _write_config(str(tmp_path), config)
    cm = ConfigManager(str(tmp_path))
    return AuthorizationManager(cm), cm
```

---

## Test Classes and Cases

### Class: `TestHelperFunctions`

Tests for the standalone helper functions — no ConfigManager needed.

| Test | Input | Expected |
|------|-------|----------|
| `test_extract_base_command_simple` | `"docker ps -a"` | `"docker"` |
| `test_extract_base_command_single_word` | `"hostname"` | `"hostname"` |
| `test_extract_base_command_with_whitespace` | `"   uptime   "` | `"uptime"` |
| `test_extract_base_command_empty` | `""` | `""` |
| `test_extract_base_command_only_spaces` | `"   "` | `""` |
| `test_split_single_command` | `"hostname"` | `["hostname"]` |
| `test_split_pipe` | `"ls \| grep foo"` | `["ls", "grep foo"]` |
| `test_split_semicolon` | `"echo hi; uptime"` | `["echo hi", "uptime"]` |
| `test_split_ampersand` | `"cmd1 & cmd2"` | `["cmd1", "cmd2"]` |
| `test_split_mixed` | `"cat file \| grep x; echo done"` | `["cat file", "grep x", "echo done"]` |
| `test_split_empty` | `""` | `[]` |
| `test_split_only_delimiters` | `";;&\|"` | `[]` |

### Class: `TestAuthResult`

| Test | Input | Expected |
|------|-------|----------|
| `test_auth_result_allowed` | `AuthResult(True, "ok", "default")` | `.allowed == True`, `.reason == "ok"`, `.matched_via == "default"` |
| `test_auth_result_denied` | `AuthResult(False, "blocked", "blocked:rm -rf")` | `.allowed == False` |

### Class: `TestCheckCommandBlockPatterns`

| Test | Input | Expected |
|------|-------|----------|
| `test_blocked_command` | `command="rm -rf /"`, `target="knubbel"` | `AuthResult(allowed=False)`, `matched_via` starts with `"blocked:"` |
| `test_blocked_case_insensitive` | `command="RM -RF /"`, `target="knubbel"` | `AuthResult(allowed=False)` |
| `test_blocked_takes_precedence` | `command="shutdown now"`, even with `"*"` in default commands | `AuthResult(allowed=False, matched_via="blocked:shutdown")` |
| `test_non_blocked_passes` | `command="hostname"`, `target="knubbel"` | `AuthResult(allowed=True)` |

### Class: `TestCheckCommandDefaultRules`

The default rules in `_minimal_auth_config` allow `hostname, uptime, free, df` for all targets (`["*"]`).

| Test | Input | Expected |
|------|-------|----------|
| `test_default_allows_listed_command` | `command="hostname"`, `target="knubbel"` | `AuthResult(allowed=True, matched_via="default")` |
| `test_default_allows_command_with_args` | `command="df -h"`, `target="knubbel"` | `AuthResult(allowed=True, matched_via="default")` |
| `test_default_denies_unlisted_command` | `command="curl http://example.com"`, `target="knubbel"`, no API key, no matching network | `AuthResult(allowed=False, matched_via="denied")` |
| `test_default_target_filter` | Create config where default has: `{"targets": ["knubbel"], "commands": ["hostname"]}` and `{"targets": ["home"], "commands": ["uptime"]}`. `command="uptime"`, `target="knubbel"` | `AuthResult(allowed=False)` (uptime rule doesn't target knubbel) |
| `test_default_wildcard_target` | `"*"` in targets means rule applies to any target | `AuthResult(allowed=True)` for a listed command on any target |
| `test_default_wildcard_commands` | `{"targets": ["*"], "commands": ["*"]}` | `command="anything"` on any target → `AuthResult(allowed=True, matched_via="default")` |

### Class: `TestCheckCommandApiKey`

These tests use `api_key="test"` (sha256 matches `monitoring-service` entry).

| Test | Input | Expected |
|------|-------|----------|
| `test_api_key_allows_listed_command` | `command="docker ps"`, `target="knubbel"`, `api_key="test"` | `AuthResult(allowed=True, matched_via="api_key:monitoring-service")` |
| `test_api_key_allows_wildcard_target` | `command="ping 8.8.8.8"`, `target="mail"`, `api_key="test"` | `AuthResult(allowed=True, matched_via="api_key:monitoring-service")` (second rule targets `["*"]` with `ping`) |
| `test_api_key_denies_wrong_target` | `command="docker ps"`, `target="mail"`, `api_key="test"` | Falls through to network/deny (docker rule only targets knubbel,home) |
| `test_api_key_full_admin` | `command="anything"`, `target="any-target"`, `api_key="foo"` | `AuthResult(allowed=True, matched_via="api_key:full-admin")` |
| `test_unknown_api_key_falls_through` | `command="curl"`, `target="knubbel"`, `api_key="unknown-key"` | Falls through to network/deny — NOT an error |
| `test_api_key_empty_string` | `api_key=""` | Treated as "no API key" → falls through |
| `test_api_key_none` | `api_key=None` | Treated as "no API key" → falls through |

### Class: `TestCheckCommandNetwork`

| Test | Input | Expected |
|------|-------|----------|
| `test_network_homelab_full_access` | `command="anything"`, `target="any"`, `source_ip="10.42.43.100"` | `AuthResult(allowed=True, matched_via="network:homelab-internal (10.42.43.0/24)")` |
| `test_network_guest_limited` | `command="uptime"`, `target="piprint"`, `source_ip="10.42.99.50"` | `AuthResult(allowed=True, matched_via="network:guest-wifi (10.42.99.0/24)")` |
| `test_network_guest_denied` | `command="docker ps"`, `target="piprint"`, `source_ip="10.42.99.50"` | Falls through to deny (guest-wifi only allows uptime,free,ping) |
| `test_network_no_match_falls_through` | `command="curl"`, `target="knubbel"`, `source_ip="192.168.1.1"` | Falls through to deny |
| `test_network_invalid_ip` | `source_ip="not-an-ip"` | Falls through silently (treat as no network match) — do NOT crash |
| `test_network_empty_string` | `source_ip=""` | Treated as "no source IP" → falls through |
| `test_network_none` | `source_ip=None` | Treated as "no source IP" → falls through |

### Class: `TestCheckCommandChainedCommands`

| Test | Input | Expected |
|------|-------|----------|
| `test_pipe_all_allowed` | `command="hostname \| grep x"`, `target="knubbel"` | Both segments (hostname, grep x) are in default rules → `AuthResult(allowed=True)` |
| `test_pipe_one_denied` | `command="hostname \| curl example.com"`, `target="knubbel"` | curl is not allowed → `AuthResult(allowed=False)` |
| `test_semicolon_all_allowed` | `command="uptime; free"`, `target="knubbel"` | Both allowed → `AuthResult(allowed=True)` |
| `test_semicolon_one_denied` | `command="uptime; rm /tmp/x"`, `target="knubbel"` | rm is not in allow list → `AuthResult(allowed=False)` |
| `test_pipe_blocked` | `command="hostname \| rm -rf /"`, `target="knubbel"` | rm -rf is blocked → `AuthResult(allowed=False, matched_via="blocked:...")` |

### Class: `TestCheckCommandEdgeCases`

| Test | Input | Expected |
|------|-------|----------|
| `test_unknown_target` | `command="hostname"`, `target="nonexistent"` | `AuthResult(allowed=False, reason="Unknown target 'nonexistent'", matched_via="denied")` |
| `test_default_overrides_api_key` | Command allowed by default → should match at default layer and stop; never checks API key | `matched_via="default"` (NOT "api_key:...") |
| `test_layer_priority_default_first` | Command in both default and API key rules → `matched_via="default"` (chain stops at first match) |
| `test_layer_fallthrough_to_api_key` | Override default to NOT have a rule for `"knubbel"` (e.g., `targets: ["home"]`). Then `api_key="test"` allows `"docker"` for `"knubbel"` | `matched_via="api_key:monitoring-service"` |
| `test_layer_fallthrough_to_network` | Default has no rule for target, no API key, but network matches → `matched_via` starts with `"network:"` |
| `test_empty_command_string` | `command=""` | `AuthResult(allowed=False)` |
| `test_block_patterns_loaded_from_config` | Change block_patterns via config → `check_command` reflects new patterns | ConfigManager hot-reload support means live data |

### Class: `TestListAllowedCommands`

| Test | Input | Expected |
|------|-------|----------|
| `test_default_only` | `target="knubbel"`, no API key, no source IP | Returns `sorted(["df", "free", "grep", "hostname", "uptime"])` |
| `test_default_plus_api_key` | `target="knubbel"`, `api_key="test"` | Returns sorted union: `["df", "docker", "free", "grep", "hostname", "journalctl", "systemctl", "uptime"]` (default + monitoring-service rules for knubbel) |
| `test_wildcard_short_circuits` | API key is `"foo"` (full-admin, commands=`["*"]`) | Returns `["*"]` immediately |
| `test_network_wildcard_short_circuits` | `source_ip="10.42.43.100"` (homelab-internal, commands=`["*"]`) | Returns `["*"]` |
| `test_unknown_target` | `target="nonexistent"` | Returns `[]` |
| `test_target_specific_filtering` | `target="mail"`, `api_key="test"` | Default: `["df", "free", "grep", "hostname", "uptime"]`. API key for mail: only `["df", "free", "ping", "uptime"]` (second rule since first only targets knubbel,home). Union is `["df", "free", "grep", "hostname", "ping", "uptime"]` sorted |
| `test_empty_result_when_nothing_matches` | Config with no default rules matching target, no API key, no network | Returns `[]` |

---

## Test Execution

Tests run via:
```bash
python -m pytest tests/test_auth.py -v
```

Or via the Makefile:
```bash
make test
```
(which runs `python -m pytest tests/ -v --ignore=tests/integration/`)

---

## Acceptance Criteria

All tests pass. The test file imports from `lib.auth` and `lib.config` only. No imports from `server.py`. No SSH connections, no HTTP, no Docker.
