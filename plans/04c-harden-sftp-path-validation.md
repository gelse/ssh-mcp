# 04c - Harden SFTP Path Validation with realpath and Sandbox

**Parent Plan**: [04-security.md](plans/04-security.md)

## Objective
Add `os.path.realpath()` resolution, null byte rejection, and configurable sandbox directory enforcement to SFTP path validation.

## Context
Current path validation in [`server.py:252`](server.py:252) only checks `os.path.isabs()` and `os.pardir`. It doesn't resolve symlinks, reject null bytes, or enforce a sandbox directory.

## Implementation Steps
1. Update `FileTransferService._validate_path()` (from task 01b) to:
   - Reject null bytes (`\x00`) in path
   - Apply `os.path.normpath()` to clean `//` and `./`
   - Apply `os.path.realpath()` to resolve symlinks
   - Check resolved path starts with sandbox root
2. Add `sandbox_root` parameter to `FileTransferService.__init__()`:
   - Default: `"/"` (full access, current behavior)
   - Configurable: `"/home/app/sftp"` restricts to subdirectory
3. Add `sandbox_root` to config schema under `settings.sftp_sandbox_root`
4. Move path validation from `server.py` to `FileTransferService`
5. Add parametrized tests with traversal payloads:
   - `../../../etc/passwd`, `//etc/passwd`, `/tmp/../etc/passwd`
   - Symlink traversal (if test environment supports it)
   - Null byte: `file.txt\x00.js`
   - Path within sandbox: `/home/app/sftp/data.txt` ✓
   - Path outside sandbox: `/etc/passwd` ✗

## Dependencies
- Task 01b (FileTransferService must exist)

## Acceptance Criteria
- Paths resolved with `os.path.realpath()` before validation
- Null bytes rejected with clear error
- Sandbox root enforced (configurable, defaults to `/`)
- Parametrized tests for 10+ traversal payloads
- Valid paths within sandbox still work
