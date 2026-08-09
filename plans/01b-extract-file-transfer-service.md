# 01b - Extract FileTransferService Class

**Parent Plan**: [01-clean-architecture.md](plans/01-clean-architecture.md)

## Objective
Extract SFTP file transfer logic from [`server.py`](server.py:252) and [`server.py`](server.py:298) into a dedicated `lib/file_transfer.py` module.

## Context
Currently, [`ssh_download_file()`](server.py:252) and [`ssh_upload_file()`](server.py:298) MCP tools contain inline SFTP operations, path validation, and file I/O. These concerns should be in a dedicated service class.

## Implementation Steps

1. Create `lib/file_transfer.py` with class `FileTransferService`:
   - `__init__(self, ssh_client_manager: SSHClientManager)`
   - `download(target_name: str, remote_path: str) -> bytes` — downloads file, returns content
   - `upload(target_name: str, remote_path: str, content: bytes) -> None` — uploads content to file
   - `_validate_path(path: str) -> str` — validates and normalizes the path
   - `_validate_sandbox(path: str) -> None` — checks path is within allowed sandbox

2. Extract path validation from both tools:
   - Absolute path check (`os.path.isabs()`)
   - Parent directory traversal check (`os.pardir`)
   - Path normalization: `os.path.normpath()`, `os.path.realpath()`
   - Null byte check
   - Consolidate into single `_validate_path()` method

3. Extract SFTP operations:
   - `client.open_sftp()` → `sftp.open()` / `sftp.putfo()`
   - File reading with size limit enforcement
   - Error handling for SFTP-specific exceptions

4. Replace inline SFTP code in MCP tools:
   - `ssh_download_file()` → call `file_transfer_service.download()`
   - `ssh_upload_file()` → call `file_transfer_service.upload()`

5. Add unit tests for `FileTransferService`:
   - Test with mock `SSHClientManager` and mock `paramiko.SFTPClient`
   - Test path validation edge cases

## Dependencies
- Task 01a (SSHClientManager must exist)

## Acceptance Criteria
- `lib/file_transfer.py` exists with `FileTransferService` class
- Path validation consolidated into single method used by both download and upload
- MCP tools in `server.py` delegate to `FileTransferService`
- Unit tests for path validation with traversal attempts
- Unit tests for download/upload with mock SSH
