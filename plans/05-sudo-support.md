# Plan 05: Sudo Support (Summary)

## Master Plan — contains all context needed for implementation

---

## Overview

Add optional `sudo` support to [`ssh_execute_command`](server.py:118) so that commands can be executed with `sudo` on the remote host when the caller explicitly requests it. Sudo itself is blocked by `block_patterns` (the word "sudo" is not in the current block list, but it will be added), so it cannot be injected arbitrarily — it must be enabled via an explicit, auditable flag on the tool call.

## Motivation

When both `private_key` and `password` are configured for an SSH target (see Plan 02), the `password` is not used for SSH authentication — `private_key` takes precedence. The `password` is retained specifically for `sudo -S` usage, since `sudo` typically requires the user's password, not the SSH key.

## Proposed Design

### Tool signature change

```python
@mcp.tool()
def ssh_execute_command(server_name: str, command: str, timeout: int = 30, sudo: bool = False) -> str:
```

When `sudo=True`:
1. The `command` is wrapped: `sudo -S -p '' <command>`
2. If the SSH target has a `password`, it is piped to `sudo` via stdin: `echo '<password>' | sudo -S -p '' <command>`
3. If the target has no `password`, `sudo` attempts passwordless sudo (NOPASSWD in sudoers)
4. `sudo` itself must NOT be in the `command` string — the flag is the only way to invoke sudo
5. The authorization chain runs against the *actual command* (without `sudo` wrapper), not against `sudo`

### Block pattern addition

Add `\bsudo\b` to `block_patterns` so that raw `sudo` in a command string is always blocked:

```json
"block_patterns": [
    "\\bsudo\\b",
    "\\brm\\s+-rf\\b",
    ...
]
```

### Logging

The log entry records whether sudo was used:

```json
{
    "event": "command_execution",
    "command": "systemctl restart nginx",
    "sudo": true,
    ...
}
```

## Open Questions (to resolve during detailed planning)

1. Should `sudo` be gated behind a separate authorization rule (e.g., `allowed_commands.sudo_allowed` per target)?
2. How should the password be passed to stdin securely? (paramiko's `exec_command` stdin channel)
3. Should there be a separate `ssh_list_allowed_commands` variant that indicates which commands support sudo?
4. Should sudo-enabled commands be limited to a subset (e.g., only `systemctl`, `journalctl`)?
