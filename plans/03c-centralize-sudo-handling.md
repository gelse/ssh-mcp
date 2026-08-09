# 03c - Centralize Sudo Handling into Single Module

**Parent Plan**: [03-separation-of-concerns.md](plans/03-separation-of-concerns.md)

## Objective
Consolidate sudo validation (currently split between `auth.py` block patterns and `server.py` wrappers) into a single `lib/sudo_handler.py` module.

## Context
Sudo handling spans two modules: [`lib/auth.py`](lib/auth.py:1) blocks raw `sudo` in command strings via block patterns, and [`server.py`](server.py:174) re-validates and wraps sudo commands with `-S -p ''` or `-n` flags. This dual concern should be unified.

## Implementation Steps
1. Create `lib/sudo_handler.py` with class `SudoHandler`:
   - `is_sudo_command(command: str) -> bool`
   - `validate_sudo(target: SSHTarget, command: str) -> bool`
   - `wrap_sudo_command(command: str, target: SSHTarget) -> str`
2. Move `_is_command_sudo()` from `server.py` to `SudoHandler.is_sudo_command()`
3. Move sudo wrapping logic from `ssh_execute_command()` to `SudoHandler.wrap_sudo_command()`
4. Add `SudoHandler.validate_sudo()` that checks the target's `sudo_allowed` flag
5. In `server.py`, replace inline sudo logic with `sudo_handler.wrap_sudo_command(command, target)`
6. Add unit tests for `SudoHandler` with various sudo forms (with args, environment prefixes, etc.)

## Dependencies
- Task 02a (constants module for SUDO_COMMAND_PREFIX)

## Acceptance Criteria
- `lib/sudo_handler.py` exists with `SudoHandler` class
- `server.py` no longer contains `_is_command_sudo()` or inline sudo wrapping
- Sudo validation logic centralized in one place
- Tests cover: plain `sudo cmd`, `sudo -u user cmd`, env-prefixed sudo, passwordless flag
