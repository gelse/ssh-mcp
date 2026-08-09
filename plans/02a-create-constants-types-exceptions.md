# 02a - Create Constants, Types, and Exceptions Modules

**Parent Plan**: [02-clean-code.md](plans/02-clean-code.md)

## Objective
Define all magic strings as named constants, create TypedDict return types, and establish a custom exception hierarchy.

## Context
The codebase has magic strings like `"mcp-ssh"`, `"sha256:"`, `"50kb"` scattered across modules. Tool return types use `dict` instead of specific TypedDicts. Only `ConfigValidationError` exists as a custom exception; everything else uses `ValueError` or lets Paramiko exceptions propagate.

## Implementation Steps

1. Create `lib/constants.py`:
   ```python
   # App identity
   APP_NAME = "mcp-ssh"

   # Paths
   DEFAULT_SSH_KEY_FILENAME = "ssh_key"
   DEFAULT_CONFIG_FILENAME = "config.json"
   DEFAULT_LOG_DIRNAME = "logs"

   # Settings defaults
   DEFAULT_MAX_COMMAND_OUTPUT = "50kb"
   DEFAULT_COMMAND_TIMEOUT_SECONDS = 120
   DEFAULT_MAX_LOG_FILE_SIZE_MB = 10
   DEFAULT_MAX_LOG_BACKUP_COUNT = 5
   DEFAULT_WATCHER_INTERVAL_SECONDS = 15

   # Auth
   API_KEY_PREFIX = "sha256:"
   SUDO_COMMAND_PREFIX = "sudo"
   FALLBACK_CLIENT_IP = "127.0.0.1"
   ```

2. Create `lib/types.py`:
   ```python
   class ServerInfo(TypedDict):
       name: str
       host: str
       username: str
       port: int
       auth_type: str
       sudo_allowed: bool

   class CommandResult(TypedDict):
       server_name: str
       command: str
       stdout: str
       stderr: str
       exit_code: int
       authorized: bool
       matched_via: str | None

   class FileTransferResult(TypedDict):
       server_name: str
       path: str
       size: int

   class ToolError(TypedDict):
       error: str
   ```

3. Create `lib/exceptions.py`:
   ```python
   class MCPSSHError(Exception):
       """Base exception for all MCP-SSH errors."""
       retryable: bool = False

   class SSHConnectionError(MCPSSHError):
       retryable = True

   class SSHAuthenticationError(MCPSSHError):
       retryable = False

   class SSHTimeoutError(MCPSSHError):
       retryable = True

   class AuthorizationError(MCPSSHError):
       retryable = False

   class CommandBlockedError(AuthorizationError):
       pass

   class PathValidationError(MCPSSHError):
       retryable = False

   class FileTransferError(MCPSSHError):
       retryable = True
   ```

4. Update imports in all modules to use constants, types, and exceptions.

## Dependencies
- None (foundational)

## Acceptance Criteria
- `lib/constants.py` exists with all magic values as named constants
- `lib/types.py` exists with TypedDicts for all tool responses
- `lib/exceptions.py` exists with hierarchical exceptions
- All modules import from these files (no inline magic strings)
- `MCPSSHError` is the base for all domain exceptions
