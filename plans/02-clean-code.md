# 02 - Clean Code

## Current State Analysis

### Code Smells Identified

#### 1. Long Tool Functions
The tool functions in [`server.py`](server.py:1) are too long and do too many things:
- [`ssh_execute_command()`](server.py:190) — ~50 lines: extracts context, resolves target, checks authorization, creates SSH client, wraps sudo, executes, reads output, logs. Should be broken into 3-4 smaller functions.

#### 2. Duplicated SSH Connection Pattern
The same pattern appears in three locations:
```python
# Pattern repeated in ssh_execute_command, ssh_download_file, ssh_upload_file
target = config_manager.get_target(server_name)
client = get_ssh_client(target)
# ... use client ...
client.close()
```
This should be extracted into a context manager.

#### 3. Magic Strings
- `"mcp-ssh"` — app name repeated ([`server.py:48`](server.py:48))
- `"ssh_key"` — key filename ([`server.py:51`](server.py:51))
- `"config.json"` — config filename ([`server.py:62`](server.py:62))
- `"/logs"` — log dir ([`server.py:66`](server.py:66))
- `"sha256:"` — API key prefix ([`server.py:88`](server.py:88))
- `"sudo"` — command prefix ([`server.py:174`](server.py:174))
- `"127.0.0.1"` — fallback IP ([`server.py:97`](server.py:97))
- `"50kb"` — default max output ([`server.py:71`](server.py:71))

#### 4. Inconsistent Error Handling Patterns
- `get_ssh_client()` raises `ValueError` for some cases, lets Paramiko exceptions propagate for others
- Tool handlers catch `Exception` broadly ([`server.py:247`](server.py:247)) but don't distinguish error types
- Some errors return generic strings, others return structured messages

#### 5. Module-Level Side Effects
Multiple side effects at import time in [`server.py`](server.py:1):
- [`ensure_directories()`](server.py:62) — filesystem operations
- [`setup_logging()`](server.py:64) — logger initialization
- [`setup_middleware()`](server.py:99) — middleware registration
- Config loading and watcher startup

#### 6. Implicit Optional Handling
- [`api_key = get_api_key()`](server.py:87) returns `Optional[str]` but callers don't consistently handle None
- [`get_current_request()`](lib/request_context.py:22) can be called outside request context; returns None but callers use `getattr` redundantly

#### 7. Type Annotation Gaps
- [`config_manager`](server.py:55) and [`auth_manager`](server.py:59) are typed but some internal dicts use `Any`
- Tool return types use `dict` instead of `TypedDict` with specific shape
- Parameter types in `_check_block_patterns()` use `List[str]` but accept `Sequence[str]`

### Positive Patterns
- Single-responsibility module files (`lib/auth.py`, `lib/config.py`, `lib/loggers.py`)
- Consistent use of dataclasses (`AuthResult`, `ConfigValidationError`)
- Clean separation of public/private API via underscore prefix
- JSONL logging format is well-structured and consistent
- Config validation is thorough with field-level error tracking

### Refactoring Recommendations

1. **Extract SSH Context Manager**
```python
@contextmanager
def ssh_connection(target: SSHTarget) -> SSHClient:
    client = get_ssh_client(target)
    try:
        yield client
    finally:
        client.close()
```

2. **Define Constants Module** (`lib/constants.py`)
- App name, default paths, magic strings, protocol constants

3. **Define TypedDict Return Types** (`lib/types.py`)
- `CommandResult`, `FileTransferResult`, `ServerInfo`, `AuthCheckResult`

4. **Create Custom Exception Hierarchy** (`lib/exceptions.py`)
- `SSHConnectionError`, `AuthorizationError`, `ConfigError`, `FileTransferError`
- All inheriting from a base `MCPSSHException`

5. **Extract Tool Logic into Handler Functions**
- Each tool becomes a thin wrapper calling a handler function
- Handlers take typed parameters and return typed results
- Tools handle MCP-specific formatting only

6. **Replace Broad Exception Catches**
- Catch specific `paramiko.SSHException`, `AuthorizationError`, etc.
- Let unexpected exceptions propagate with proper logging

## Acceptance Criteria
- No function exceeds 30 lines (excluding docstrings)
- All repeated SSH connection patterns use context manager
- All magic strings defined as named constants
- Custom exception hierarchy in place
- TypedDict return types for all tool responses
- No module-level side effects in import path
