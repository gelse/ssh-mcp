# 14a - Make Internal Helpers Private, Standardize Target Names & Add Constants/Docstrings

**Parent Plan**: [14-naming-conventions-readability.md](plans/14-naming-conventions-readability.md)

## Objective
Rename internal helpers with `_` prefix, standardize `target_name` usage across the codebase, create `lib/constants.py` with all magic values, and add module docstrings to every `.py` file.

## Current Issues
- `get_ssh_client()`, `get_api_key()`, `ensure_directories()` are module-internal but lack `_` prefix, implying they're public API.
- `server_name` (tool signatures), `target_name` (config), and `name` (AuthResult) all refer to the same concept.
- Magic numbers (15, 50kb, 10, 5) and magic strings (`"mcp-ssh"`, `"sha256:"`, `"sudo"`, `"127.0.0.1"`) are scattered.
- Several modules lack docstrings (`lib/__init__.py` has only a comment).

## Implementation Steps

### 1. Rename Internal Helpers in [`server.py`](server.py:1)
- `get_ssh_client()` → `_get_ssh_client()`
- `get_api_key()` → `_get_api_key()`
- `ensure_directories()` → `_ensure_directories()`
- Update all call sites within `server.py`.
- Also rename `_check_block_patterns()` in server.py → `_build_block_pattern_error()` to differentiate from `AuthorizationManager._check_block_patterns()`.

### 2. Standardize Target Identifier Name
- All internal code uses `target_name` (function parameters, AuthResult field, log events).
- Only MCP tool function signatures keep `server_name` (API contract for external clients).
- In tool bodies, immediately rename: `target_name = server_name`.
- Update `AuthResult` dataclass: `name` → `target_name`.
- Update all references in [`lib/auth.py`](lib/auth.py:1), [`lib/config.py`](lib/config.py:1), log events, and error messages.

### 3. Create `lib/constants.py`
Define all magic values:

```python
# App identity
APP_NAME = "mcp-ssh"
APP_VERSION = "1.0.0"

# Default paths
DEFAULT_CONFIG_FILENAME = "config.json"
DEFAULT_LOG_DIR = "/logs"
DEFAULT_LOG_FILENAME = "ssh-executions.log"
DEFAULT_SSH_KEY_FILENAME = "ssh_key"

# Auth constants
API_KEY_HASH_PREFIX = "sha256:"
SUDO_COMMAND_PREFIX = "sudo"
SUDO_PASSWORD_PROMPT_FLAGS = "-S -p ''"
SUDO_NO_PASSWORD_FLAG = "-n"
FALLBACK_CLIENT_IP = "127.0.0.1"

# Default settings
DEFAULT_MAX_COMMAND_OUTPUT = "50kb"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 120
DEFAULT_MAX_LOG_FILE_SIZE_MB = 10
DEFAULT_MAX_LOG_BACKUP_COUNT = 5
DEFAULT_WATCHER_INTERVAL_SECONDS = 15

# Limits
MAX_SERVER_NAME_LENGTH = 128
MAX_API_KEY_LENGTH = 1024
MAX_REGEX_PATTERN_LENGTH = 10000
MAX_TARGETS = 1000
MAX_BLOCK_PATTERNS = 500

# SSH defaults
DEFAULT_SSH_PORT = 22
DEFAULT_SSH_TIMEOUT_SECONDS = 30

# HTTP
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVICE_UNAVAILABLE = 503
```

### 4. Replace Magic Values Across All Files
- [`server.py`](server.py:1): Replace `"mcp-ssh"`, `"ssh_key"`, `"config.json"`, `"/logs"`, `"sha256:"`, `"sudo"`, `"127.0.0.1"`, `"50kb"` with imports from `lib/constants.py`.
- [`lib/auth.py`](lib/auth.py:1): Replace `"sudo"` with `SUDO_COMMAND_PREFIX`.
- [`lib/config.py`](lib/config.py:1): Replace default values in `_validate_config()` with constant references.
- [`lib/loggers.py`](lib/loggers.py:1): Replace `_current_log_path` → `_log_path`.

### 5. Add Module Docstrings
Every `.py` file gets a one-line module docstring:

| File | Docstring |
|------|-----------|
| `server.py` | `"""FastMCP SSH server — MCP tools for remote command execution, file transfer, and server management."""` |
| `lib/__init__.py` | `"""MCP-SSH library: configuration, authorization, logging, and request utilities."""` |
| `lib/auth.py` | `"""AuthorizationManager with layered authorization: block patterns → default → API key → network → deny."""` |
| `lib/config.py` | `"""ConfigManager with JSON loading, strict validation, and hot-reload via file watcher."""` |
| `lib/loggers.py` | `"""Structured JSONL logging with size-based rotation."""` |
| `lib/health.py` | `"""Health check endpoint for container orchestration."""` |
| `lib/request_context.py` | `"""Request context middleware via ContextVar for per-request IP and API key access."""` |

### 6. Update All Tests
- Update test references to renamed functions (`_get_ssh_client`, `_get_api_key`).
- Standardize test names that use `server_name` → `target_name` in test fixtures.
- Rename generic test class names (e.g., `TestHelperFunctions` → `TestRequestContextHelpers`).

## Dependencies
- Task 02a (constants/types/exceptions — this task creates the actual `constants.py` module)
- Task 02b (context manager — uses renamed `_get_ssh_client`)

## Acceptance Criteria
- All internal helpers in `server.py` have `_` prefix
- `target_name` used consistently in all internal code (only `server_name` in MCP tool signatures)
- `lib/constants.py` defines all magic values and is imported wherever they're used
- Every `.py` file has a module docstring
- `_current_log_path` renamed to `_log_path`
- `AuthResult.name` renamed to `AuthResult.target_name`
- All existing tests pass with renamed symbols
