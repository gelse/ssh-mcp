# Security Model

This document describes the security architecture of the SSH MCP server, the
threats it mitigates, and how to configure and operate it securely.

---

## Table of Contents

- [Transport Security](#transport-security)
- [API Key Authentication](#api-key-authentication)
- [Command Authorization](#command-authorization)
- [Path Traversal Prevention](#path-traversal-prevention)
- [Rate Limiting](#rate-limiting)
- [Network Authorization](#network-authorization)
- [Secure Defaults](#secure-defaults)
- [Configuration Hardening](#configuration-hardening)
- [Vulnerability Reporting](#vulnerability-reporting)

---

## Transport Security

**The SSH MCP server is designed to run behind a TLS-terminating reverse proxy
(e.g. nginx, Caddy, Traefik).** The built-in HTTP server listens on
`0.0.0.0:8080` in plain HTTP. Exposing it directly to untrusted networks
without TLS will leak API keys in transit.

Recommended deployment pattern:

```
Client  ──[HTTPS]──►  Reverse Proxy  ──[HTTP]──►  mcp-ssh :8080
```

The reverse proxy should:

- Terminate TLS with a valid certificate.
- Strip the `X-Forwarded-For` header from untrusted sources and set it to the
  real client IP.
- (Optional) Enforce IP allowlisting for the `/mcp` path at the proxy level.

---

## API Key Authentication

### Hashing

API keys stored in the configuration file are hashed using **PBKDF2-HMAC-SHA256**
with 100,000 iterations and a 16-byte random per-key salt. The stored format is:

```
pbkdf2:sha256:100000$<salt_hex>$<hash_hex>
```

Legacy SHA-256 hashes (prefixed `sha256:`) are still accepted during
verification for backward compatibility, but **new keys are always stored in
the PBKDF2 format**.

### Timing Safety

Key comparison uses [`secrets.compare_digest()`] to resist timing side-channel
attacks. An attacker cannot determine how close a guess is by measuring
response time.

### Best Practices

- Generate API keys with at least 128 bits of entropy (e.g. `openssl rand -hex 32`).
- Store only hashes in `config.json` — never plaintext keys.
- Rotate keys regularly, especially if a key may have been exposed.
- Remove legacy `sha256:` hashes and re-hash them with PBKDF2.

[`secrets.compare_digest()`]: https://docs.python.org/3/library/secrets.html#secrets.compare_digest

---

## Command Authorization

The authorization engine uses a **layered decision chain** evaluated in order:

```
block_patterns → default → api_key → network → deny
```

### 1. Block Patterns (`block_patterns`)

Regex patterns defined in `config.json` that unconditionally deny commands
matching destructive or dangerous operations. Examples:

| Pattern               | Blocks                                      |
|-----------------------|---------------------------------------------|
| `\bsudo\b`            | Privilege escalation via sudo               |
| `\brm\s+-rf\b`        | Recursive forced deletion                   |
| `\bdd\s+if=`          | Direct disk writes                          |
| `\bshutdown\b`        | System shutdown                             |
| `\breboot\b`          | System reboot                               |

### 2. Dangerous Shell Patterns

Before any rule evaluation, commands are scanned for shell metacharacters
that enable injection:

- `$()` — command substitution
- Backticks — deprecated command substitution
- `\n` / `\r` — newline injection

These patterns are **always denied**, regardless of quoting or context.

### 3. Command Segmentation

Multi-segment commands joined by pipes (`|`), semicolons (`;`), or `&&`/`||`
are split into individual segments. **Each segment runs through the full
authorization chain independently.** If any segment is denied, the entire
command is denied.

### 4. POSIX Shell Tokenization

Command parsing uses [`shlex.split()`] for POSIX-compliant tokenization,
preventing whitespace normalization attacks. The extracted command basename
is validated against a character whitelist (`[a-zA-Z0-9][a-zA-Z0-9_-]*`).

[`shlex.split()`]: https://docs.python.org/3/library/shlex.html#shlex.split

---

## Path Traversal Prevention

SFTP file transfer paths are validated through **seven layers of defense**:

| Layer | Check | Threat Mitigated |
|-------|-------|------------------|
| 1 | Path is not empty | Null/invalid input |
| 2 | No null bytes | Poisoned-string attacks |
| 3 | No dangerous Unicode | Homoglyph attacks (e.g. `∕` instead of `/`) |
| 4 | URL-decoded form has no `..` | Double-encoding (`%2e%2e%2f`) |
| 5 | Path components not `.`, `..`, or `~` | Direct traversal |
| 6 | `normpath` result is absolute | Relative-path escape |
| 7 | `realpath` result starts with sandbox root | Symlink escape |

The sandbox root is configured via `settings.sftp_sandbox_root` and defaults
to `"/"` (full access). To restrict file transfers, set it to a subdirectory
such as `"/home/app/sftp"`.

---

## Rate Limiting

Per-IP rate limiting uses a **sliding-window algorithm** with the following
defaults:

| Setting                    | Default | Description                                |
|----------------------------|---------|--------------------------------------------|
| `max_requests_per_minute`  | 60      | Maximum requests per client IP per window  |
| `window_seconds`           | 60.0    | Sliding-window duration                    |
| `cleanup_interval_seconds` | 300.0   | Stale-entry garbage collection interval    |

When a client exceeds the limit, the server returns:

```
HTTP 429 Too Many Requests
Retry-After: 60
```

The `/health` endpoint is **never** rate-limited.

These values can be overridden in `config.json` under
`settings.rate_limit`:

```json
{
  "settings": {
    "rate_limit": {
      "max_requests_per_minute": 120,
      "window_seconds": 30.0,
      "cleanup_interval_seconds": 600.0
    }
  }
}
```

### Thread Safety

All rate-limit state is guarded by a single `threading.Lock`. The lock is
held only for the duration of the in-memory deque operation, ensuring minimal
contention. Periodic cleanup prevents unbounded memory growth from abandoned
IP addresses.

---

## Network Authorization

The authorization engine supports **IP-based allowlisting** bound to specific
API keys. When configured, a command is only allowed if the client's source
IP matches one of the permitted CIDR ranges:

```json
{
  "allowed_commands": {
    "networks": [
      {
        "api_key_id": "ops-team-key",
        "ranges": ["10.0.0.0/8", "172.16.0.0/12"],
        "commands": ["docker", "systemctl", "journalctl"]
      }
    ]
  }
}
```

Network rules are evaluated **after** API key rules in the authorization chain,
providing defense-in-depth: a stolen API key is useless from outside the
approved network range.

---

## Secure Defaults

The server ships with conservative defaults designed for production safety:

| Default                        | Value                  | Rationale                              |
|--------------------------------|------------------------|----------------------------------------|
| API key hashing                | PBKDF2-SHA256, 100k    | Resistant to offline brute-force       |
| Command timeout                | 120 seconds            | Prevents runaway remote processes      |
| Max output length              | 50,000 characters      | Prevents LLM context exhaustion        |
| Max file transfer size         | 10 MiB                 | Prevents disk-fill attacks             |
| Dangerous pattern detection    | Enabled unconditionally | Prevents command injection             |
| Path traversal checks          | 7-layer validation     | Defense-in-depth for SFTP paths        |
| Per-IP rate limiting           | 60 req/min             | Mitigates brute-force and DoS          |
| Non-root container user        | `mcpssh`               | Limits impact of container escape      |
| `--no-cache-dir` in Dockerfile | Enabled                | Reduces image size and attack surface  |

---

## Configuration Hardening

### Secrets Management

- SSH private keys should be mounted as files (Docker secrets or Kubernetes
  secrets), never baked into the image.
- The `password` field on SSH targets supports environment-variable
  substitution (`${ENV_VAR}` syntax).
- API keys should be hashed before writing to `config.json`. The server
  provides `hash_api_key()` in [`lib/crypto.py`](../lib/crypto.py) for
  offline hashing.

### File Permissions

- `config.json` should be readable only by the `mcpssh` user (`chmod 600`).
- SSH private keys should be readable only by the `mcpssh` user.
- The log directory should be writable by `mcpssh` but not world-readable
  (logs may contain command output and server names).

### Environment Variables

Sensitive values can be injected at runtime:

| Variable          | Purpose                        |
|-------------------|--------------------------------|
| `CONFIG_DIR`      | Path to configuration directory |
| `LOG_DIR`         | Path to log output directory   |
| `SSH_KEY_PATH`    | Path to SSH private key        |
| `MAX_OUTPUT_LENGTH` | Max command output length    |

---

## Vulnerability Reporting

If you discover a security vulnerability in this project, please **do not**
open a public issue. Instead, report it privately:

1. **Email**: Open a private security advisory through the repository's
   Security tab, or contact the maintainers directly.
2. **Scope**: Include a clear description of the vulnerability, steps to
   reproduce, and the affected versions.
3. **Response**: The maintainers aim to acknowledge reports within 48 hours
   and provide an initial assessment within 5 business days.

### Out of Scope

- Vulnerabilities in third-party dependencies (report to the upstream project).
- Denial-of-service attacks that require an already-authenticated client
  (rate limiting provides basic mitigation).
- Social engineering or phishing attacks against operators.

---

## Related Documentation

- [API Key Hashing](../lib/crypto.py) — `hash_api_key()` and `verify_api_key()`
- [Command Security](../lib/command_security.py) — `check_dangerous_patterns()` and `segment_command()`
- [File Transfer Security](../lib/file_transfer.py) — `_validate_path()` with 7-layer checks
- [Authorization Engine](../lib/auth.py) — Layered decision chain
- [Rate Limiter](../lib/rate_limiter.py) — Sliding-window implementation
