# Plan 03d: Migrate MCP Tools to AuthorizationManager

## Prerequisites
- Plan 03a (`lib/auth.py`) — `AuthorizationManager` class exists and passes all tests
- Plan 03b (`tests/test_auth.py`) — all unit tests pass
- Plan 03c (`lib/request_context.py` + `server.py` changes) — `extract_client_ip()`, `extract_api_key()`, `auth_manager` singleton, middleware registered, old functions removed

## Subtask
Update the tool function bodies in [`server.py`](server.py) to use `AuthorizationManager` for authorization decisions. Also add the new `ssh_list_allowed_commands` tool.

## Files to Modify

| File | Change |
|------|--------|
| [`server.py`](server.py) | Update `ssh_execute_command()`, `ssh_download_file()`, `ssh_upload_file()` to use `auth_manager`; add `ssh_list_allowed_commands()` tool |

## Files to Create

*None.* All new code goes into existing files (already created in Plans 03a/03c).

---

## 1. `ssh_execute_command()` — Updated Authorization Flow

Replace the current [`ssh_execute_command()`](server.py:191) body with the new auth chain. The function signature stays the same: `ssh_execute_command(server_name: str, command: str, timeout: int = 30) -> str`.

### Updated logic

```python
@mcp.tool()
def ssh_execute_command(server_name: str, command: str, timeout: int = 30) -> str:
    """
    Execute a command on a remote SSH server.

    The command is validated against the layered authorization chain:
    block_patterns -> default -> API key -> network -> deny.

    Args:
        server_name: The identifier of the SSH server (as configured)
        command: The command to execute
        timeout: Command timeout in seconds (1-300)

    Returns:
        Command output (stdout + stderr combined) or auth denial reason
    """
    # --- Authorization check ---
    source_ip = extract_client_ip()
    api_key = extract_api_key()

    auth_result = auth_manager.check_command(
        command=command,
        target=server_name,
        source_ip=source_ip,
        api_key=api_key,
    )

    if not auth_result.allowed:
        logger.warning(
            "AUTH DENIED: target=%s command=%s source_ip=%s matched_via=%s reason=%s",
            server_name, command, source_ip,
            auth_result.matched_via, auth_result.reason,
        )
        return f"Command rejected: {auth_result.reason}"

    logger.info(
        "AUTH ALLOWED: target=%s command=%s source_ip=%s matched_via=%s",
        server_name, command, source_ip, auth_result.matched_via,
    )

    # --- Execute command (existing logic, unchanged) ---
    timeout = max(1, min(timeout, config_manager.data.get("settings", {}).get("command_timeout_max", 300)))

    client = get_ssh_client(server_name)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        error_output = stderr.read().decode("utf-8", errors="replace")

        max_len = config_manager.data.get("settings", {}).get("max_output_length", 100000)
        if len(output) > max_len:
            output = output[:max_len] + "\n... (truncated)"
        if len(error_output) > max_len:
            error_output = error_output[:max_len] + "\n... (truncated)"

        return output + ("\n" + error_output if error_output.strip() else "")
    except Exception as e:
        logger.error("SSH execution failed for %s: %s", server_name, e)
        return f"Error executing command on {server_name}: {str(e)}"
```

### Key changes from current code

| Aspect | Old | New |
|--------|-----|-----|
| Authorization | `validate_command(command)` → calls `check_block_patterns` + `is_command_allowed` | `auth_manager.check_command(command, server_name, source_ip, api_key)` |
| Client identity | Not extracted (all clients treated equally) | `extract_client_ip()` + `extract_api_key()` from request context |
| Auth logging | None | `logger.warning(...)` on deny, `logger.info(...)` on allow |
| Denial response | `"Security policy violation: ..."` or `"Command not allowed: ..."` | `"Command rejected: <reason>"` |
| Error messages | References to `validate_command` and `is_command_allowed` | Clean error messages using `auth_result.reason` |

---

## 2. `ssh_download_file()` — Authorization Check

The download tool currently has no authorization check at all (line 234-252). Add authorization using the `"cat"` command as the logical equivalent:

```python
@mcp.tool()
def ssh_download_file(server_name: str, remote_path: str) -> str:
    """
    Download a file from a remote SSH server.

    Requires authorization equivalent to executing 'cat <remote_path>'.
    The authorization chain is: block_patterns -> default -> API key -> network -> deny.

    Args:
        server_name: The identifier of the SSH server (as configured)
        remote_path: Absolute path to the file on the remote server

    Returns:
        File contents as a string, or auth denial reason
    """
    # Authorization: file download requires "cat" permission
    source_ip = extract_client_ip()
    api_key = extract_api_key()

    auth_result = auth_manager.check_command(
        command="cat",
        target=server_name,
        source_ip=source_ip,
        api_key=api_key,
    )

    if not auth_result.allowed:
        logger.warning(
            "AUTH DENIED (download): target=%s path=%s source_ip=%s matched_via=%s",
            server_name, remote_path, source_ip, auth_result.matched_via,
        )
        return f"Download rejected: {auth_result.reason}"

    logger.info(
        "AUTH ALLOWED (download): target=%s path=%s matched_via=%s",
        server_name, remote_path, auth_result.matched_via,
    )

    # --- Execute download (existing logic, unchanged) ---
    client = get_ssh_client(server_name)
    try:
        sftp = client.open_sftp()
        try:
            with sftp.file(remote_path, "r") as f:
                content = f.read().decode("utf-8", errors="replace")
            return content
        finally:
            sftp.close()
    except Exception as e:
        logger.error("SFTP download failed for %s:%s: %s", server_name, remote_path, e)
        return f"Error downloading file from {server_name}: {str(e)}"
```

---

## 3. `ssh_upload_file()` — Authorization Check

The upload tool (line 254-276) currently has no authorization check. Use `"tee"` as the logical equivalent (writing a file):

```python
@mcp.tool()
def ssh_upload_file(server_name: str, remote_path: str, content: str, permissions: str = "0644") -> str:
    """
    Upload a file to a remote SSH server.

    Requires authorization equivalent to executing 'tee <remote_path>'.
    The authorization chain is: block_patterns -> default -> API key -> network -> deny.

    Args:
        server_name: The identifier of the SSH server (as configured)
        remote_path: Absolute path to write the file to on the remote server
        content: The file contents to write
        permissions: File permissions as an octal string (e.g. "0644")

    Returns:
        Success message or auth denial reason
    """
    # Authorization: file upload requires "tee" permission
    source_ip = extract_client_ip()
    api_key = extract_api_key()

    auth_result = auth_manager.check_command(
        command="tee",
        target=server_name,
        source_ip=source_ip,
        api_key=api_key,
    )

    if not auth_result.allowed:
        logger.warning(
            "AUTH DENIED (upload): target=%s path=%s source_ip=%s matched_via=%s",
            server_name, remote_path, source_ip, auth_result.matched_via,
        )
        return f"Upload rejected: {auth_result.reason}"

    logger.info(
        "AUTH ALLOWED (upload): target=%s path=%s matched_via=%s",
        server_name, remote_path, auth_result.matched_via,
    )

    # --- Execute upload (existing logic, unchanged) ---
    client = get_ssh_client(server_name)
    try:
        sftp = client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
            sftp.chmod(remote_path, int(permissions, 8))
        finally:
            sftp.close()
        return f"File uploaded successfully to {server_name}:{remote_path}"
    except Exception as e:
        logger.error("SFTP upload failed for %s:%s: %s", server_name, remote_path, e)
        return f"Error uploading file to {server_name}: {str(e)}"
```

---

## 4. `ssh_list_allowed_commands()` — NEW Tool

Add a new tool between `ssh_list_servers` and `ssh_execute_command`:

```python
@mcp.tool()
def ssh_list_allowed_commands(server_name: str) -> str:
    """
    List all commands the current client is allowed to execute on a given server.

    Considers all applicable layers: default rules, API key rules, and network rules.
    Returns a sorted, deduplicated list of allowed command base names.
    If the wildcard "*" is allowed via any layer, returns just "*".

    Does NOT check block_patterns — block patterns may further restrict commands
    at execution time.

    Args:
        server_name: The identifier of the SSH server (as configured)

    Returns:
        JSON-formatted list of allowed command base names, or error message
    """
    source_ip = extract_client_ip()
    api_key = extract_api_key()

    commands = auth_manager.list_allowed_commands(
        target=server_name,
        source_ip=source_ip,
        api_key=api_key,
    )

    return json.dumps(commands)
```

**Placement**: Insert this function between `ssh_list_servers` and `ssh_execute_command` in [`server.py`](server.py). Add `import json` at the top of the file if not already present.

### Design Decision: Why `json.dumps()` instead of raw string?

The MCP tool returns a string (as per the `-> str` signature). Returning JSON is the standard machine-readable format that MCP clients can parse. Alternative considered was newline-separated text — rejected because JSON is standard for MCP.

---

## 5. `get_ssh_client()` — No Changes

The [`get_ssh_client()`](server.py:125) function remains unchanged. It's already separated from authorization and only handles SSH client connection. All authorization is done in the tool functions before calling `get_ssh_client()`.

---

## 6. `ssh_list_servers()` — No Changes

This function already reads from `config_manager` (line 179 of [`server.py`](server.py:174)). No authorization is needed for listing servers — the list of server names is not sensitive. No changes required.

---

## Additional Import Required

In [`server.py`](server.py), ensure these imports are present (some may already be added by plan 03c):

```python
import json         # for ssh_list_allowed_commands
import logging      # for logger

from lib.request_context import get_current_request  # added by plan 03c
```

The `logger` should be defined at module level:
```python
logger = logging.getLogger(__name__)
```

---

## Edge Cases & Decisions

| Scenario | Behavior |
|----------|----------|
| Client is denied by block_patterns | `ssh_execute_command` returns `"Command rejected: blocked by pattern '<pattern>'"` |
| Client is denied because no rule matches | Returns `"Command rejected: denied: not in any allow list for target <target>"` |
| Unknown target (not in config) | Returns `"Command rejected: Unknown target '<target>'"` — this is checked before any SSH connection attempt |
| `extract_client_ip()` returns `None` (no request context) | `source_ip=None` passed to auth; only default rules apply |
| `extract_api_key()` returns `None` (no auth header) | `api_key=None` passed to auth; only default + network rules apply |
| File download denied | Returns `"Download rejected: <reason>"` |
| File upload denied | Returns `"Upload rejected: <reason>"` |
| `timeout` parameter exceeds config limit | Clamped to `config_manager.data["settings"]["command_timeout_max"]` (existing behavior, unchanged) |
| `timeout` parameter below 1 | Clamped to minimum of 1 (existing behavior, unchanged) |

---

## What This Subtask Does NOT Do

- Does NOT change the SSH execution logic in `get_ssh_client()` — only adds auth checks before calling it
- Does NOT modify the timeout clamping logic
- Does NOT modify the output truncation logic
- Does NOT change `ssh_list_servers()` — it already reads from ConfigManager
- Does NOT add new SSH capabilities — only adds authorization gates to existing tools and one read-only listing tool
- Does NOT log to a file (logging to file is in plan 04)

---

## Acceptance Criteria

1. `ssh_execute_command("knubbel", "hostname")` with no API key or special network → executes successfully (allowed by default rules)
2. `ssh_execute_command("knubbel", "rm -rf /")` → denied by block_patterns, returns `"Command rejected: blocked by pattern 'rm\s+'"` (or similar)
3. `ssh_execute_command("nonexistent", "hostname")` → returns `"Command rejected: Unknown target 'nonexistent'"`
4. `ssh_execute_command("knubbel", "curl http://evil.com")` with no matching rules → returns denial message
5. `ssh_download_file("knubbel", "/etc/hostname")` → authorization checked with `"cat"` command
6. `ssh_upload_file("knubbel", "/tmp/test.txt", "hello")` → authorization checked with `"tee"` command
7. `ssh_list_allowed_commands("knubbel")` → returns JSON array of allowed command names
8. `ssh_list_allowed_commands("nonexistent")` → returns `"[]"`
9. The server starts without errors (imports resolve, middleware attaches)
10. Existing tests in [`tests/test_server.py`](tests/test_server.py) continue to pass (these tests recreate logic inline and don't import the tool functions)
11. [`tests/test_e2e_config.py`](tests/test_e2e_config.py) continues to pass (tests ConfigManager, not tools)
