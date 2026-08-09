# 01a - Extract SSHClientManager Class

**Parent Plan**: [01-clean-architecture.md](plans/01-clean-architecture.md)

## Objective
Extract SSH client creation logic from [`server.py`](server.py:152) into a dedicated `lib/ssh_client.py` module.

## Context
Currently, [`get_ssh_client()`](server.py:152) lives in `server.py` and handles:
- SSH key file loading (Ed25519/RSA detection via PEM headers)
- Password authentication setup
- SSHClient creation, socket configuration, connect timeout
- This is infrastructure code mixed into the application layer

## Implementation Steps

1. Create `lib/ssh_client.py` with class `SSHClientManager`:
   - `__init__(self, ssh_key_path: str | None = None)` — stores default key path
   - `create_client(self, target: SSHTarget) -> paramiko.SSHClient` — creates and connects client
   - `_load_key(self, key_path: str) -> paramiko.PKey` — key type detection and loading
   - `_configure_client(self, client: paramiko.SSHClient, target: SSHTarget) -> None` — connect

2. Move key-loading logic from `get_ssh_client()`:
   - Read the key file, detect PEM header type
   - Load with appropriate Paramiko key class
   - Handle missing key files with clear errors

3. Move SSH client configuration:
   - `set_missing_host_key_policy(paramiko.AutoAddPolicy())`
   - `connect()` with hostname, username, port, timeout
   - Handle both key-based and password-based auth

4. Replace `get_ssh_client()` in [`server.py`](server.py:152) with calls to `SSHClientManager`

5. Update all call sites: [`ssh_execute_command()`](server.py:190), [`ssh_download_file()`](server.py:252), [`ssh_upload_file()`](server.py:298)

## Dependencies
- None (this is foundational; other refactors depend on this)

## Acceptance Criteria
- `lib/ssh_client.py` exists with `SSHClientManager` class
- `server.py` no longer imports `paramiko` directly (or only for type hints)
- All existing tests pass
- `SSHClientManager` can be instantiated with a mock key path for testing
