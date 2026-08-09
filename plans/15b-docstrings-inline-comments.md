# 15b - Add Docstrings & Inline Comments for Complex Logic

**Parent Plan**: [15-documentation-inline-comments.md](plans/15-documentation-inline-comments.md)

## Objective
Add Google-style docstrings to all public functions and methods in [`server.py`](server.py:1) and [`lib/`](lib/). Add explanatory inline comments for complex logic: authorization chain, command segmentation, key loading, IP extraction, and sudo wrapping.

## Current Gaps
- `_extract_client_ip()` — no docstring
- `_is_command_sudo()` — no docstring
- `_get_ssh_client()` — no docstring
- `_ensure_directories()` — no docstring
- `_get_api_key()` — no docstring
- Complex logic has no inline comments explaining rationale
- Private methods in `lib/auth.py` have no docstrings

## Implementation Steps

### 1. Add Docstrings to All Undocumented Functions

#### [`server.py`](server.py:1) Helpers

```python
def _ensure_directories() -> None:
    """Create required directories for logs if they don't exist.

    Creates the log directory specified by `log_dir`. Used during startup
    to ensure the logging subsystem can write immediately.
    """
```

```python
def _get_api_key() -> Optional[str]:
    """Extract the API key from the current HTTP request's X-API-Key header.

    Must be called within an active request context (ASGI middleware has run).
    Returns None if called outside a request or if no key header is present.
    """
```

```python
def _extract_client_ip() -> str:
    """Extract the client IP from HTTP headers with proxy awareness.

    Checks headers in order:
    1. X-Forwarded-For: Takes the leftmost (original client) IP.
       ⚠ Only trust this behind a trusted reverse proxy (Traefik).
    2. X-Real-IP: Fallback for simple proxy setups.
    3. Returns '127.0.0.1' if no headers found.

    Extracts only the first IP from comma-separated X-Forwarded-For values.
    No IP format validation is performed here (see lib/sanitize.py).
    """
```

```python
def _is_command_sudo(command: str, target: dict) -> bool:
    """Check if a command string starts with 'sudo'.

    Used to determine whether sudo wrapping is needed. The actual sudo
    wrapping (adding -S -p '' or -n flags) is done at execution time.
    """
```

```python
def _get_ssh_client(target: SSHTarget) -> paramiko.SSHClient:
    """Create and connect a Paramiko SSH client for the given target.

    Handles:
    - SSH key loading: Ed25519 (OPENSSH format), RSA (PKCS#1), PKCS#8
    - Password authentication fallback
    - Missing host key policy (AutoAddPolicy — acceptable behind proxy)

    Raises:
        SSHError: If key format is unrecognized
        paramiko.SSHException: On connection or authentication failure
        FileNotFoundError: If the SSH key file doesn't exist
    """
```

#### [`lib/auth.py`](lib/auth.py:1) Private Methods

```python
def _split_command_segments(self, command: str) -> List[str]:
    """Split a command string into segments on shell operators.

    Splits on |, &, and ; to detect piped/chained commands. Each segment
    must pass authorization independently. The regex is tested during
    config validation to ensure it compiles correctly.
    """

def _check_block_patterns(self, command: str) -> Optional[str]:
    """Check if the command matches any globally blocked regex pattern.

    Returns the matched pattern string if blocked, None if allowed.
    Patterns are compiled once during AuthorizationManager initialization
    for performance.

    ⚠ Each pattern must be safe — no catastrophic backtracking (ReDoS).
    Patterns are validated at config load time.
    """

def _match_api_key(self, api_key_hash: str) -> Optional[dict]:
    """Find API key rules matching the given key hash.

    Returns the key's rule dict (commands, description) or None.
    Uses constant-time comparison to prevent timing attacks.
    """

def _match_network(self, client_ip: str) -> Optional[dict]:
    """Find network rules matching the client's IP address.

    Checks the IP against all configured CIDR ranges. Uses ipaddress
    module for proper network matching. Returns the matching network's
    rule dict or None.
    """
```

#### [`lib/config.py`](lib/config.py:1) Private Methods

```python
def _validate_config(self, config: dict) -> None:
    """Validate the complete configuration structure.

    Checks top-level keys, SSH targets, block patterns, allowed commands,
    API keys, and settings. Collects all errors before raising to give
    the operator a complete picture of what needs fixing.
    """

def _validate_ssh_targets(self, targets: list) -> None:
    """Validate SSH target definitions: required fields, types, port range,
    auth configuration consistency, and uniqueness of target names.
    """

def _validate_block_patterns(self, patterns: list) -> None:
    """Validate that all block patterns are valid, compilable regex strings
    with no catastrophic backtracking risks.
    """

def _validate_allowed_commands(self, commands: dict) -> None:
    """Validate the allowed_commands structure: default list plus optional
    per-api-key and per-network rules with command lists.
    """
```

#### [`lib/loggers.py`](lib/loggers.py:1)

```python
def _rotate_if_needed(self) -> None:
    """Check if the current log file exceeds the size limit and rotate if so.

    Rotation: renames current log → <name>.1, shifts .1→.2, etc.
    Oldest backup beyond max_backup_count is deleted. All operations
    are performed under the write lock for thread safety.
    """
```

### 2. Add Inline Comments for Complex Logic

#### Authorization Chain in [`lib/auth.py:check_command()`](lib/auth.py:1)
```python
def check_command(self, command: str, api_key: Optional[str] = None,
                  client_ip: Optional[str] = None) -> AuthResult:
    # Layer 1: Global block patterns — always checked first
    # These are catch-all deny rules for dangerous commands (rm -rf, etc.)
    blocked = self._check_block_patterns(command)
    if blocked:
        return AuthResult(allowed=False, reason=f"Blocked pattern: {blocked}")

    # Layer 2: Default allowlist — base set of safe commands
    # If a command isn't in the default list, no amount of API key or
    # network authorization can allow it
    segments = self._split_command_segments(command)
    ...
    if not all(seg in self.default_allowed for seg in segments):
        return AuthResult(allowed=False, reason="Not in default allowlist")

    # Layer 3: API key rules — override default with per-client permissions
    # Layer 4: Network rules — override default with per-subnet permissions
    # Layer 5: Implicit deny — command passed default but no elevated rules match
```

#### Command Segmentation in [`lib/auth.py`](lib/auth.py:1)
```python
# Split on shell operators: pipe (|), background (&), command separator (;)
# This prevents: `allowed_cmd | dangerous_cmd` from passing authorization
# when only `allowed_cmd` is in the allowlist.
_SEGMENT_SPLIT_RE = re.compile(r'[|&;]')
```

#### Key Loading in [`server.py:152`](server.py:152)
```python
# PEM header inspection determines key format:
# - "BEGIN OPENSSH PRIVATE KEY"  → Ed25519 (modern, preferred)
# - "BEGIN RSA PRIVATE KEY"      → RSA PKCS#1 (legacy)
# - "BEGIN PRIVATE KEY"           → PKCS#8 (generic container, assume Ed25519)
#
# We check the header line rather than the file extension because the
# extension may not match the actual format.
_KEY_LOADERS = { ... }
```

#### IP Extraction in [`server.py:93`](server.py:93)
```python
# X-Forwarded-For format: "client, proxy1, proxy2"
# When behind Traefik, Traefik appends to this header. The leftmost IP is
# the original client. ⚠ Without a trusted proxy, this header can be spoofed.
# X-Real-IP: Set by nginx/Traefik to the immediate upstream client IP.
```

#### Sudo Wrapping in [`server.py`](server.py:1)
```python
# sudo -S -p '' : Read password from stdin, empty prompt (avoids prompt in output)
# sudo -n       : Non-interactive mode — fails if password is needed
# Strategy: Use password-mode when the target has a password, non-interactive
# when using key-based auth (sudoers configured with NOPASSWD).
```

#### SFTP Path Validation in [`server.py`](server.py:252)
```python
# Path validation strategy:
# 1. os.path.isabs()  → Must be absolute (no relative path confusion)
# 2. os.pardir check  → Reject paths containing .. (parent traversal)
# 3. null byte check  → Reject paths with \x00 (path truncation attacks)
# Note: realpath() cannot be used pre-connection because the file may
# not exist yet (upload case). Symlink checks happen server-side.
```

## Dependencies
- Task 14a (renames `get_ssh_client` → `_get_ssh_client` — docstrings apply to renamed functions)

## Acceptance Criteria
- Every function in `server.py` has a docstring (public + private)
- Every public method in `lib/auth.py`, `lib/config.py`, `lib/loggers.py` has a docstring
- Every private method in `lib/auth.py`, `lib/config.py`, `lib/loggers.py` has a brief docstring
- Authorization chain has inline comments explaining each layer
- Command segmentation regex has explanatory comment
- Key loading dispatch table has PEM header explanation
- IP extraction has proxy trust model comment
- Sudo wrapping has `-S -p ''` and `-n` flag documentation
- SFTP path validation strategy is documented
