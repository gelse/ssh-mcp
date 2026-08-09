# 05 - Test Coverage

## Current State Analysis

### Test Inventory

| File | Classes/Functions | Focus |
|------|-------------------|-------|
| [`tests/test_auth.py`](tests/test_auth.py:1) | 10 test classes | Authorization logic |
| [`tests/test_config.py`](tests/test_config.py:1) | 4 test classes | Config loading, validation, watcher |
| [`tests/test_e2e_config.py`](tests/test_e2e_config.py:1) | 8 standalone functions | Real config file pipeline |
| [`tests/test_loggers.py`](tests/test_loggers.py:1) | 6 test classes | Logger behavior, rotation |
| [`tests/test_server.py`](tests/test_server.py:1) | 10 test classes | Server-level logic (mostly monkeypatched) |
| [`tests/integration/test_integration.py`](tests/integration/test_integration.py:1) | Docker-based | Full MCP protocol with real SSH |

### Coverage Gaps by Module

#### `lib/auth.py`
- ✓ Block pattern matching (including regex)
- ✓ Default rules
- ✓ API key matching
- ✓ Network matching (CIDR)
- ✓ Command segmentation (pipe, ampersand, semicolon)
- ✓ `list_allowed_commands()`
- ✓ `AuthResult` dataclass properties
- ✗ Edge: Unicode homoglyphs in commands
- ✗ Edge: Very long command strings
- ✗ Edge: Empty segment lists
- ✗ Edge: Overlapping API key and network rules

#### `lib/config.py`
- ✓ Valid config loading
- ✓ Validation failures (missing fields, invalid types)
- ✓ Default config creation
- ✓ Hot-reload (change detection, invalid rejection)
- ✓ Thread safety (concurrent reads during reload)
- ✓ `ConfigValidationError` field tracking
- ✗ Edge: Very large config files
- ✗ Edge: Malformed JSON (not just invalid schema)
- ✗ Edge: Config file deletion during operation
- ✗ Edge: Symlink config files

#### `lib/loggers.py`
- ✓ JSONL format output
- ✓ Unicode handling
- ✓ Size-based rotation
- ✓ Thread-safe writes
- ✓ `close()` behavior
- ✗ Edge: Disk full during write
- ✗ Edge: Permission denied on log directory
- ✗ Edge: Concurrent rotation + write race
- ✗ Edge: Extremely large single log lines

#### `server.py` (module-level logic)
- ✓ `_extract_client_ip()` header parsing
- ✓ `_is_command_sudo()` detection
- ✓ Sudo wrapping (with/without password)
- ✓ Config/log dir resolution from env
- ✗ `get_ssh_client()` — not directly tested (monkeypatched)
- ✗ `get_api_key()` — not directly tested
- ✗ `ensure_directories()` — not tested
- ✗ `setup_logging()` — not tested
- ✗ Tool functions themselves — not unit-tested (only integration)
- ✗ `_check_block_patterns()` server wrapper

#### No Tests At All
- [`lib/health.py`](lib/health.py:1) — health endpoint
- [`lib/request_context.py`](lib/request_context.py:1) — middleware
- [`lib/__init__.py`](lib/__init__.py:1) — N/A
- [`Dockerfile`](Dockerfile:1) — no container structure tests
- [`compose.yaml`](compose.yaml:1) — no compose validation

### Testing Approach Issues

1. **server.py Tests Use Logic Simulation**
   Many tests in [`tests/test_server.py`](tests/test_server.py:1) reimplement logic inline rather than importing the module. Example: `_is_sudo_command()` tests reimplement the regex rather than calling the actual function. This means the tests validate their own logic, not the production code.

2. **Heavy Monkeypatching**
   `tests/test_server.py` monkeypatches `os.environ`, `pathlib.Path`, and uses mocks extensively. This is fragile and doesn't test actual integration between modules.

3. **No Parametrized Attack Vectors**
   Security-critical code (auth, command segmentation) should have parametrized tests with known attack vectors. Currently uses hand-written cases.

4. **No Property-Based Testing**
   No use of Hypothesis or similar for generating edge cases.

### Coverage Improvement Plan

1. **Add Tests for Untested Modules**
   - `tests/test_health.py` — Test health endpoint returns 200 + correct JSON
   - `tests/test_request_context.py` — Test middleware sets/clears context
   - `tests/test_ssh_client.py` — Test SSH client creation, key loading, connection failures (mock paramiko)

2. **Rewrite server.py Tests to Import Actual Code**
   - Import `server` module in test fixtures
   - Test `get_ssh_client()` with mocked `paramiko.SSHClient`
   - Test `get_api_key()` with mock Starlette Request
   - Test tool functions with dependency injection

3. **Add Parametrized Security Tests**
   - `@pytest.mark.parametrize` with command injection payloads
   - Known path traversal payloads for SFTP
   - Authentication bypass attempts

4. **Add Edge Case Coverage**
   - Empty inputs
   - Maximum-size inputs
   - Concurrent operations
   - Resource exhaustion scenarios

### Acceptance Criteria
- Line coverage ≥ 85% for `lib/` modules
- Every public function has at least one test
- Security-critical paths have parametrized attack vector tests
- `server.py` tests import and call actual code (not simulations)
- New test files for previously untested modules
