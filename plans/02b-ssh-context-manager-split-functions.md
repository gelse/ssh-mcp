# 02b - Extract SSH Context Manager & Split Long Functions

**Parent Plan**: [02-clean-code.md](plans/02-clean-code.md)

## Objective
Create an SSH connection context manager to eliminate duplicated connection patterns and split long tool functions into smaller, focused units.

## Context
Three MCP tools ([`ssh_execute_command()`](server.py:190), [`ssh_download_file()`](server.py:252), [`ssh_upload_file()`](server.py:298)) each repeat the pattern: resolve target → create SSH client → use client → close client. Additionally, `ssh_execute_command()` at ~50 lines does too many things.

## Implementation Steps

1. Add context manager to `SSHClientManager` (`lib/ssh_client.py`):
   ```python
   @contextmanager
   def connect(self, target_name: str) -> paramiko.SSHClient:
       target = self._config_manager.get_target(target_name)
       if not target:
           raise SSHConnectionError(f"Unknown target: {target_name}")
       client = self.create_client(target)
       try:
           yield client
       finally:
           client.close()
   ```

2. Split `ssh_execute_command()` into smaller functions:
   - `_resolve_target_and_auth(server_name, command, ip, api_key)` → (target, auth_result)
   - `_wrap_sudo_command(command, target)` → (wrapped_command)
   - `_execute_and_capture(client, command, timeout)` → (stdout, stderr, exit_code)
   - Tool body becomes: resolve → authorize → wrap sudo → execute → log

3. Split `ssh_download_file()` into:
   - `_validate_download_path(remote_path)` → validated_path
   - `_download_bytes(client, remote_path)` → bytes
   - Tool body becomes: resolve path → connect → download → return

4. Split `ssh_upload_file()` into:
   - `_validate_upload_path(remote_path)` → validated_path
   - `_upload_bytes(client, remote_path, content)` → None
   - Tool body becomes: resolve path → connect → upload → return

5. Convert all tools to use the `with ssh_client_manager.connect(target_name) as client:` pattern.

6. Ensure no function exceeds 30 lines (excluding docstrings and blank lines).

## Dependencies
- Task 01a (SSHClientManager must exist)
- Task 01c (factory pattern — tools need injected services)

## Acceptance Criteria
- `SSHClientManager.connect()` context manager exists
- All three tools use the context manager (no manual `client.close()`)
- `ssh_execute_command()` split into functions ≤30 lines each
- `ssh_download_file()` and `ssh_upload_file()` simplified
- All existing tests pass
