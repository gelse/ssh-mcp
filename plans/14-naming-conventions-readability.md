# 14 - Naming Conventions & Readability

## Current State Analysis

### Naming Assessment by Module

#### `server.py`

| Name | Type | Assessment |
|------|------|------------|
| `mcp` | FastMCP instance | ✓ Clear, standard |
| `config_manager` | ConfigManager | ✓ Descriptive |
| `auth_manager` | AuthorizationManager | ✓ Descriptive |
| `logger` | FileLogger | ✓ Clear |
| `ssh_key_path` | Path | ✓ Snake case |
| `config_path` | Path | ✓ Snake case |
| `log_dir` | Path | ✓ Snake case |
| `ssh_list_servers()` | MCP tool | ✓ Verb-first, snake case |
| `ssh_execute_command()` | MCP tool | ✓ Verb-first |
| `ssh_download_file()` | MCP tool | ✓ Verb-first |
| `ssh_upload_file()` | MCP tool | ✓ Verb-first |
| `ssh_list_allowed_commands()` | MCP tool | ✓ Verb-first |
| `_extract_client_ip()` | Helper | ✓ Private prefix |
| `_is_command_sudo()` | Helper | ✓ Private prefix |
| `_check_block_patterns()` | Helper | ✓ Private prefix |
| `get_ssh_client()` | Helper | ⚠ Should be private `_get_ssh_client()` |
| `get_api_key()` | Helper | ⚠ Should be private `_get_api_key()` |
| `ensure_directories()` | Helper | ⚠ Should be private `_ensure_directories()` |

#### `lib/auth.py`

| Name | Type | Assessment |
|------|------|------------|
| `AuthorizationManager` | Class | ✓ PascalCase, descriptive |
| `AuthResult` | Dataclass | ✓ PascalCase |
| `check_command()` | Method | ✓ Verb-first |
| `list_allowed_commands()` | Method | ✓ Verb-first |
| `_check_block_patterns()` | Method | ✓ Private prefix |
| `_split_command_segments()` | Method | ✓ Verb-first, private |
| `_match_api_key()` | Method | ✓ Verb-first, private |
| `_match_network()` | Method | ✓ Verb-first, private |

#### `lib/config.py`

| Name | Type | Assessment |
|------|------|------------|
| `ConfigManager` | Class | ✓ PascalCase |
| `ConfigValidationError` | Exception | ✓ PascalCase, Error suffix |
| `_validate_config()` | Method | ✓ Private prefix |
| `_validate_ssh_targets()` | Method | ✓ Verb-first |
| `_validate_block_patterns()` | Method | ✓ Verb-first |
| `_validate_allowed_commands()` | Method | ✓ Verb-first |

#### `lib/loggers.py`

| Name | Type | Assessment |
|------|------|------------|
| `BaseLogger` | ABC | ✓ PascalCase |
| `FileLogger` | Class | ✓ PascalCase |
| `_rotate_if_needed()` | Method | ✓ Verb-first, private |
| `_current_log_path` | Property | ⚠ Should be `_log_path` — "current" is redundant |

### Issues Identified

#### 1. Inconsistent Private/Public Boundary
[`server.py`](server.py:1): `get_ssh_client()`, `get_api_key()`, and `ensure_directories()` are module-internal helpers but lack `_` prefix. This implies they're part of the public API when they're not.

#### 2. Unclear Function Names
- `_check_block_patterns()` in [`server.py`](server.py:1) vs `_check_block_patterns()` in [`lib/auth.py`](lib/auth.py:1) — same name, different purpose. The server version wraps the auth version.
- Consider: `_build_block_pattern_error()` for the server wrapper.

#### 3. Inconsistent Suffix Usage
- `ssh_execute_command` / `ssh_download_file` / `ssh_upload_file`: "ssh_" prefix is redundant since all tools are SSH-related. But removing it would break the MCP API. Consider documenting the naming convention.
- File transfer tools use `ssh_download_file` but the tool name is the verb+noun pattern rather than noun-first.

#### 4. Variable Name Inconsistency
- `server_name` used in tool signatures
- `target_name` used internally in config
- `name` used in AuthResult dataclass
These all refer to the same concept (SSH target identifier) but use different names.

#### 5. Magic Number Naming
- `15` (watcher interval default) — should be `DEFAULT_WATCHER_INTERVAL_SECONDS`
- `50kb` (max output default) — should be `DEFAULT_MAX_COMMAND_OUTPUT`
- `10` (max log size default) — should be `DEFAULT_MAX_LOG_FILE_SIZE_MB`
- `5` (log backup count) — should be `DEFAULT_MAX_LOG_BACKUP_COUNT`

#### 6. Config Key Naming
[`default-config.json`](default-config.json:1): Uses `snake_case` keys. This is consistent and good. Verify all keys follow this pattern — no accidental `camelCase`.

#### 7. Test Naming
Tests use `test_<function>_<scenario>` pattern which is good. However:
- Some test class names don't fully describe the scope (e.g., `TestHelperFunctions` — which helpers?)
- Integration test file name `test_integration.py` is generic — consider `test_mcp_protocol.py` or similar

#### 8. No Module Docstrings
[`lib/__init__.py`](lib/__init__.py:1) has only a comment. Library modules should have brief docstrings describing their purpose and exports.

### Readability Issues

#### 1. Dense Conditional Logic
[`get_ssh_client()`](server.py:152) has deeply nested conditionals for key type detection. The RSA vs Ed25519 logic could be extracted into clearer helpers:
```python
# Current: nested if/elif checking PEM headers
# Better: dispatch table or strategy pattern
KEY_LOADERS = {
    'ed25519': lambda f: paramiko.Ed25519Key.from_private_key(f),
    'rsa': lambda f: paramiko.RSAKey.from_private_key(f),
}
```

#### 2. Long Comprehensions
Some list/dict comprehensions span multiple lines without clear formatting.

#### 3. Implicit Boolean Checks
`if len(key) > 0:` instead of `if key:` — the former is overly explicit.

#### 4. Commented-Out Code
Check for any residual commented-out code or debug prints.

### Naming & Readability Improvements

1. **Make Internal Helpers Private**
   - `get_ssh_client()` → `_get_ssh_client()`
   - `get_api_key()` → `_get_api_key()`
   - `ensure_directories()` → `_ensure_directories()`

2. **Standardize Target Identifier Name**
   - Always use `target_name` internally (not `server_name` or just `name`)
   - Keep `server_name` only in MCP tool signatures (API contract)

3. **Define All Constants**
   - `lib/constants.py` with all defaults, magic strings, limits

4. **Add Module Docstrings**
   - Every `.py` file gets a one-line module docstring
   - `__init__.py` re-exports important symbols

5. **Simplify Key Loading**
   - Extract key type detection into a dispatch table
   - Add `_load_ssh_key(key_path)` helper

6. **Consistent Tool Naming Convention** (Document, Don't Change)
   - Document that tool names use `ssh_<verb>_<noun>` pattern
   - Add this to developer documentation

7. **Improve Test Names**
   - Rename generic class names to be more descriptive
   - Add module-level test docstrings

8. **Line Length**
   - Enforce 100-character line limit (PEP 8 recommends 79, but 100 is modern standard)
   - Add `.editorconfig` or `pyproject.toml` with formatter settings

### Acceptance Criteria
- All internal helpers use `_` prefix
- Consistent use of `target_name` across codebase
- `lib/constants.py` defines all magic values
- Every module has a docstring
- Key loading uses dispatch pattern, not nested if/elif
- `.editorconfig` added with line length and indentation rules
- No line exceeds 100 characters
