# 04 - Security

## Current State Analysis

### Authorization Chain (Layered, Correct)
```
block_patterns → default rules → api_key rules → network rules → deny
```
The layered approach in [`lib/auth.py`](lib/auth.py:1) is well-designed with early-exit semantics. Each layer short-circuits on match.

### Security Issues Identified

#### 1. API Key Hashing is Non-Cryptographic
[`server.py:88`](server.py:88): `sha256(key.encode()).hexdigest()` uses a single SHA-256 with no salt. This is vulnerable to:
- **Rainbow table attacks**: Identical API keys produce identical hashes
- **No key stretching**: SHA-256 is fast; brute-force is cheap
- **No pepper/salt**: Even a static pepper would require attackers to rebuild tables

**Recommendation**: Use `hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100_000)` with per-key random salts stored alongside the hash. Alternatively, use `secrets.compare_digest()` for timing-safe comparison (currently uses `==`).

#### 2. IP Authorization Uses String Comparison
[`lib/auth.py`](lib/auth.py:1) network matching likely uses [`ipaddress.ip_network()`](lib/auth.py) correctly, but verify that:
- IPv4-mapped IPv6 addresses are handled consistently
- Private/loopback IPs are flagged or rejected by default
- The `127.0.0.1` fallback in [`server.py:97`](server.py:97) doesn't accidentally authorize loopback

#### 3. No Rate Limiting
No mechanism limits:
- Failed authentication attempts
- Command execution frequency per client
- Repeated blocked command attempts (potential brute-force enumeration)

#### 4. Command Injection via Pipes/Chains
The command segmenter in [`_split_command_segments()`](lib/auth.py) splits on `|&;` characters and checks each segment independently. Potential bypasses:
- **Backtick substitution**: `` `cmd` `` in shells
- **$() substitution**: `$(cmd)` expansion
- **Newline injection**: `cmd\nmalicious` not split by segmenter
- **Unicode homoglyphs**: Unicode characters that look like `|` but aren't ASCII
- **Environment variable expansion**: `$VAR`, `${VAR}` not checked

#### 5. SFTP Path Traversal
Path validation in download/upload checks `os.path.isabs()` and `os.pardir` but:
- Symlink following not prevented (`os.path.realpath()` should be used on the resolved path)
- Null byte injection not checked (`\x00` in path)
- Multiple slashes (`//etc/passwd`) may bypass checks depending on OS
- No sandbox directory enforcement — paths can reference any file the SSH user can access

#### 6. Sudo Command Handling
[`_is_sudo_command()`](server.py:174) matches `sudo` at the start of a command but:
- `sudo` with arguments before the command could bypass: `sudo -u root cmd` vs `sudo cmd`
- Environment variable prefix: `VAR=val sudo cmd`
- Alias expansion: if the server has `alias sudo=...` (mitigated by non-interactive shell)
- The `sudo_allowed` target flag is checked, but there's no per-command sudo allowlist

#### 7. Sensitive Data in Logs
Command output logging in [`server.py`](server.py:1):
- Full command output written to JSONL logs
- Could contain passwords, tokens, secrets from command results
- No redaction or truncation for sensitive patterns

#### 8. Dockerfile Security
[`Dockerfile`](Dockerfile:1):
- Runs as non-root user `mcpssh` ✓
- No `--no-cache-dir` on pip install — leaves pip cache in image
- No image scanning in build pipeline
- HEALTHCHECK uses `wget` — should use `curl` or Python for smaller surface

#### 9. No TLS Configuration in FastMCP
The FastMCP server likely runs HTTP. TLS termination is delegated to Traefik in [`compose.yaml`](compose.yaml:1) — this should be documented as a security requirement.

### Security Hardening Recommendations

1. **Upgrade API Key Storage**
   - Use PBKDF2 with per-key random salts
   - Store salt alongside hash: `pbkdf2:sha256:100000$<salt>$<hash>`
   - Use `secrets.compare_digest()` for comparison

2. **Add Rate Limiting**
   - Per-IP rate limit on all MCP endpoints
   - Exponential backoff for failed auth
   - Configurable limits in `default-config.json` settings

3. **Harden Command Segmentation**
   - Add check for `$(` and backtick substitution
   - Add newline character check
   - Add `&&`, `||` as segment delimiters (currently only `|&;`)
   - Consider a whitelist approach: only allow semicolons, disallow all other metacharacters

4. **Harden SFTP Path Validation**
   - Resolve paths with `os.path.realpath()` before checking
   - Enforce a configurable base directory (sandbox)
   - Reject paths containing null bytes
   - Normalize paths before validation

5. **Add Output Sanitization for Logs**
   - Truncate output at a configurable log limit (separate from response limit)
   - Optionally redact patterns matching common secrets (API keys, passwords)

6. **Harden Docker Build**
   - Add `--no-cache-dir` to pip install
   - Pin all dependency versions with hashes
   - Consider multi-stage build to minimize attack surface

7. **Document TLS Requirement**
   - Add `SECURITY.md` documenting that TLS must be provided by reverse proxy
   - Warn against exposing FastMCP HTTP port directly

### Acceptance Criteria
- API keys use PBKDF2 with per-key salts and timing-safe comparison
- Command segmentation catches `$()`, backticks, newlines, `&&`, `||`
- SFTP paths resolved with `realpath()` and sandbox enforcement
- Rate limiting configurable in settings
- Dockerfile uses `--no-cache-dir` and pinned dependencies
- `SECURITY.md` documents TLS/reverse proxy requirement
