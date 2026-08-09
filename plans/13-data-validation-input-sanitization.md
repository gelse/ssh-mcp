# 13 - Data Validation & Input Sanitization

## Current State Analysis

### Validation Points

| Input | Location | Validation | Status |
|-------|----------|------------|--------|
| Config file schema | [`lib/config.py`](lib/config.py:1) | Strict type/value checking | ✓ Good |
| Command strings | [`lib/auth.py`](lib/auth.py:1) | Regex block patterns, segmentation | ⚠ Needs hardening |
| Server names | [`server.py`](server.py:1) | Lookup in target list | ✓ Adequate |
| File paths (SFTP) | [`server.py`](server.py:252) | isabs, pardir check | ⚠ Needs hardening |
| IP addresses | [`server.py`](server.py:93) | Basic string parsing | ⚠ Needs validation |
| API key hashes | [`server.py`](server.py:88) | Length check `len(key) > 0` | ⚠ Minimal |
| SSH key types | [`server.py`](server.py:152) | Explicit type check | ✓ Good |
| Port numbers | [`lib/config.py`](lib/config.py:1) | Integer range validation | ✓ Good |
| Log file paths | [`lib/loggers.py`](lib/loggers.py:1) | None — accepts any string | ✗ Missing |
| Output size | [`server.py`](server.py:1) | max_command_output limit | ✓ Good |

### Issues Identified

#### 1. API Key Validation — Insufficient
[`server.py:88`](server.py:88): `sha256(key.encode()).hexdigest()` only checks `len(key) > 0`. Missing:
- Maximum key length (prevent DoS with multi-MB "keys")
- Character validation (only printable ASCII expected)
- Timing-safe comparison (`==` leaks timing information)

#### 2. IP Address Extraction — No Validation
[`server.py:93`](server.py:93): `_extract_client_ip()` splits on commas, strips whitespace, and returns the first entry. Missing:
- IP format validation (is it actually an IP?)
- IPv6 handling in X-Forwarded-For
- Malformed header handling (doesn't crash but may return garbage)
- Trusted proxy configuration (header can be spoofed)

#### 3. Server Name Validation — No Constraints
Target names from config have no validation beyond being strings:
- No length limits
- No character restrictions (could include `/`, `..`, control chars)
- Used in log messages and error responses without sanitization
- Could be used for log injection if containing newlines

#### 4. Command String Sanitization
Before authorization check, commands are received raw:
- Null bytes not stripped
- Control characters not stripped (e.g., ANSI escape sequences)
- Unicode normalization not applied (NFKC to catch homoglyph attacks)
- Leading/trailing whitespace not stripped consistently

#### 5. Path Validation — Incomplete
[`server.py:252`](server.py:252) and [`server.py:298`](server.py:298):
- `os.path.isabs()` — Unix only (what about Windows clients?)
- `os.pardir` check — only catches `..`, not symlink traversal
- Null byte not checked
- Path length not limited
- No sandbox root enforcement

#### 6. Config Field Length Validation
[`lib/config.py`](lib/config.py:1): Schema validation checks types and required fields, but:
- No max length for target `name`, `host`, `username`
- No max number of targets
- No max number of block patterns
- No max regex complexity limits (ReDoS via catastrophic backtracking)

#### 7. Regex Injection in Block Patterns
Block patterns are user-provided regex. If a malicious operator adds a pattern like `(a+)+b` with a carefully crafted input, it causes ReDoS (exponential backtracking). No complexity limit on patterns.

#### 8. No Input Normalization
Commands, server names, and file paths are not normalized:
- Unicode NFKC normalization for commands (catch homoglyphs)
- Path normalization (`os.path.normpath()`)
- Whitespace normalization

### Validation Improvements

1. **API Key Hardening**
   - Max key length: 1024 characters
   - Validate printable ASCII only
   - Use `secrets.compare_digest()` for hash comparison
   - Reject non-hex characters in stored hashes

2. **IP Address Validation**
   - Validate with `ipaddress.ip_address()` before use
   - Handle IPv4-mapped IPv6: `::ffff:192.168.1.1`
   - Reject obviously invalid IPs
   - Add configurable trusted proxy list

3. **Server Name Constraints**
   - Max 128 characters
   - Allowed chars: `[a-zA-Z0-9._-]+`
   - Sanitize before use in log messages

4. **Command Input Sanitization Pipeline**
   ```
   raw_command
     → strip null bytes
     → strip control chars (except \t, \n, \r)
     → NFKC unicode normalization
     → strip leading/trailing whitespace
     → validated command
   ```

5. **Path Validation Hardening**
   ```
   raw_path
     → reject null bytes
     → os.path.normpath()
     → os.path.realpath()
     → check within sandbox root
     → check not traversing via symlinks
     → validated path
   ```

6. **Config Resource Limits**
   - Max 1000 targets
   - Max 500 block patterns
   - Max 10000 characters per regex pattern
   - Max target name length: 128

7. **Regex Safety**
   - Use `re.compile(pattern, re.LIMITED_TIME)` or similar
   - Alternatively, pre-test patterns against known-safe inputs
   - Add timeout wrapper for regex matching

8. **Log Injection Prevention**
   - Sanitize all user-provided values before logging
   - Strip newlines from fields that shouldn't contain them
   - Use structured logging (already JSONL) to prevent injection

### Acceptance Criteria
- API key comparison uses `secrets.compare_digest()`
- IP addresses validated with `ipaddress` module
- Server names restricted to `[a-zA-Z0-9._-]{1,128}`
- Command input goes through sanitization pipeline before auth
- SFTP paths validated with `realpath()` and sandbox check
- Config resource limits enforced
- Regex patterns checked for ReDoS safety
- All user-provided values sanitized before logging
