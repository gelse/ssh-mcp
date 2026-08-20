# Security Model

This document describes the security architecture of the SSH MCP server, the
threats it mitigates, and how to configure and operate it securely.

---

## Table of Contents

- [Transport Security](#transport-security)
- [API Key Authentication](#api-key-authentication)
- [Command Authorization](#command-authorization)
- [Input Sanitization](#input-sanitization)
- [Path Traversal Prevention](#path-traversal-prevention)
- [Rate Limiting](#rate-limiting)
- [Network Authorization](#network-authorization)
- [Secure Defaults](#secure-defaults)
- [Configuration Hardening](#configuration-hardening)
- [Client IP Extraction](#client-ip-extraction)
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

### Client IP Extraction

The effective client IP used for rate limiting and network authorization is
resolved by [`lib/request_context.py`](lib/request_context.py) from two
sources, in order:

1. **`X-Forwarded-For` header** — but **only** when the direct connection peer
   is listed in the `settings.trusted_proxies` configuration list. An empty
   `trusted_proxies` list (the default) means **no proxy is trusted** and the
   header is ignored entirely, falling back to the direct peer IP.
2. **Direct peer IP** (`request.client.host`) — used whenever the header is
   absent, untrusted, malformed, or empty.

The extracted value is always normalized and validated using the standard
library `ipaddress` module:

- **Invalid IPs are rejected.** Values that fail `ipaddress.ip_address()` (for
  example `not-an-ip`, `999.999.999.999`, or trailing garbage) are discarded
  and the caller falls back to `FALLBACK_CLIENT_IP`.
- **IPv4-mapped IPv6 is collapsed.** `::ffff:192.168.1.1` is normalized to
  `192.168.1.1` so that IPv4 addresses carried over IPv6 do not bypass
  IPv4-based allowlists or rate-limit keys.
- **Whitespace is trimmed.** Leading/trailing whitespace around the first
  `X-Forwarded-For` entry is removed before validation.
- **Untrusted headers are ignored.** If the direct peer is not in
  `trusted_proxies`, the `X-Forwarded-For` header is never honored, defeating
  spoofed-header attacks against the rate limiter and network authorization.

`trusted_proxies` entries are validated at config load time with
`ipaddress.ip_address()` and normalized the same way, so only syntactically
valid IP addresses can be trusted.

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
block_patterns
  → dangerous patterns
  → redirection-target guard
  → strip redirectors
  → command segmentation
  → default
  → api_key
  → network
  → deny
```

All rules are compiled once into an immutable, frozen `RulesSnapshot`
(`block_patterns`, `default` rules, API-key rules, and network rules) and swapped
atomically as a single reference assignment on reload. A reader therefore never
observes a partially-updated rule set, even while the config is being hot-reloaded.

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

#### ReDoS Protection

Because `block_patterns` are evaluated against every command, a pathological
pattern could otherwise become a denial-of-service vector (catastrophic
backtracking). Three defense layers mitigate this:

1. **Load-time static screening** — each pattern is scanned by
   `check_redos_risk()` for known ReDoS-prone constructs (nested quantifiers like
   `(a+)+`, overlapping alternation like `(a|a)+`, and quantified dot-star groups
   like `(.*a){n}`). A risky pattern invalidates the whole config and is rejected.
2. **`re.LIMITED_TIME`** — where the host Python provides it, block patterns are
   compiled with the engine's time-limited matching flag so the regex engine
   itself bounds matching time.
3. **Hard timeout on match** — every block-pattern match runs through
   `safe_regex_search()`, which executes the search on a single-worker thread and
   aborts past a wall-clock timeout. On timeout the match is treated as **no
   match** (i.e. the command is NOT blocked) so an attacker cannot force a block
   or starve the executor.

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

Before segmentation, unquoted redirection operators and their targets are
**stripped from the command** (`strip_redirects`). This prevents a
"phantom-segment" denial where a redirection such as `2>&1 | grep` is
tokenized on the `&` and mis-parsed as invalid pipeline structure (which would
deny otherwise-valid commands like `ls -la 2>&1 | grep proc`). Only the
**segmentation** step uses the stripped string; `block_patterns` and the
dangerous-pattern scan always operate on the **raw** command string first, so
stripping never hides a redirector that a denial pattern should catch.

The strip is intentionally conservative:

- **`fd-dup` / `fd-close`** forms are removed: `2>&1`, `>&2`, `2>&-`, `&>`.
- **file-redirect** forms and their target filenames are removed: `2>`, `1>`,
  `>`, `>>`, `2>>`, `&>>`.
- **Here-docs / here-strings** (`<<`, `<<<`), quoted redirectors, and redirect
  targets embedded in quotes are **out of scope** and left untouched.

### Redirection Target Guard (defense-in-depth)

As a belt-and-braces control, commands are also scanned (via
`PROTECTED_REDIRECT_TARGET_RE`) for redirection into sensitive device and
pseudo-filesystem paths (`/dev/`, `/proc/`, `/sys/`). Any match is denied with
`matched_via: blocked:redirection-target`. This runs **after** `block_patterns`
and **before** the dangerous-pattern scan, so even a malformed or quoted
redirector that escapes stripping cannot write to protected paths.

### 4. POSIX Shell Tokenization

Command parsing uses [`shlex.split()`] for POSIX-compliant tokenization,
preventing whitespace normalization attacks. The extracted command basename
is validated against a character whitelist (`[a-zA-Z0-9][a-zA-Z0-9_-]*`).

[`shlex.split()`]: https://docs.python.org/3/library/shlex.html#shlex.split

## Input Sanitization

Before any input reaches the authorization chain or logging, user-controlled
fields are sanitized by [`lib/sanitize.py`](../lib/sanitize.py). This is a
first-line defense, applied **before** authorization so that downstream checks
operate on a predictable, normalized value.

### Command sanitization (`sanitize_command`)

Every `command` argument is normalized via a fixed pipeline:

1. **Null-byte stripping** — embedded `\x00` bytes are removed.
2. **Control-character removal** — all control bytes except `\t`, `\n`, and `\r`
   are stripped, which neutralizes ANSI escape sequences and other terminal or
   log injection primitives.
3. **NFKC normalization** — Unicode is normalized to NFKC, collapsing
   visually-confusable characters and removing homoglyph bypasses.
4. **Whitespace trimming** — leading/trailing whitespace is removed.

`\n` and `\r` are **deliberately preserved** through sanitization: newline and
carriage-return injection are denied later by the dangerous shell-pattern scan
(see [Dangerous Shell Patterns](#2-dangerous-shell-patterns)). If they were
stripped here, payloads relying on them would pass the sanitizer and then be
denied by the same dangerous-pattern scan — so preserving them keeps the
authorization decision correct, not just after the fact.

### Target-name sanitization (`sanitize_target_name`)

`server_name` must match `[a-zA-Z0-9._-]{1,128}`. Leading/trailing whitespace
is trimmed, then the value is validated against the regex and the
`MAX_TARGET_NAME_LENGTH` upper bound; invalid values raise `AuthorizationError`
and are denied at the handler boundary.

### Log-string sanitization (`sanitize_log_string`)

`command` and `server_name` (and remote-path display) fields that are written
to JSONL logs are passed through `sanitize_log_string`, which collapses `\r`
and `\n` to a single space. This prevents JSONL **log-injection**, where a
crafted value could otherwise forge additional log lines or alter the shape of
a log record.

---

## Path Traversal Prevention

SFTP file transfer paths are validated through **eight layers of defense**:

| Layer | Check | Threat Mitigated |
|-------|-------|------------------|
| 1 | Path is not empty | Null/invalid input |
| 2 | No null bytes | Poisoned-string attacks |
| 3 | No dangerous Unicode | Homoglyph attacks (e.g. `∕` instead of `/`) |
| 4 | URL-decoded form has no `..` | Double-encoding (`%2e%2e%2f`) |
| 5 | Path components not `.`, `..`, or `~` | Direct traversal |
| 6 | `normpath` result is absolute | Relative-path escape |
| 7 | `realpath` result starts with sandbox root | Symlink escape |
| 8 | Path length within configured limit | Protocol-level buffer overflows |

The sandbox root is configured via `settings.sftp.sandbox_root` and defaults
to `"/"` (full access). To restrict file transfers, set it to a subdirectory
such as `"/home/app/sftp"`.

The maximum path length is configured via `settings.sftp.max_path_length` and
defaults to `4096` bytes. Set to `0` to disable the length check.

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

These values can be overridden in `ssh-mcp-config.json` under
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

### Request context fallbacks

The request-context accessors in [`lib/request_context.py`](lib/request_context.py)
return safe fallback values when called outside an active request context
(e.g. during startup, shutdown, or background tool execution):

| Accessor                | Fallback                | Notes                                        |
|-------------------------|-------------------------|----------------------------------------------|
| `get_client_ip()`       | `127.0.0.1`             | Loopback never grants external allow-list IP |
| `get_api_key()`         | `None`                  | No key available outside a request           |
| `get_request_id()`      | `"unknown"`             | Non-empty for log/error correlation     |
| `get_current_request()` | `None`                  | Must be null-checked before dereferencing    |

Callers must null-check `get_current_request()` (and any `None`-capable
accessors) rather than assuming a request is always in progress.

---

## Secure Defaults

The server ships with conservative defaults designed for production safety:

| Default                        | Value                  | Rationale                              |
|--------------------------------|------------------------|----------------------------------------|
| API key hashing                | PBKDF2-SHA256, 100k    | Resistant to offline brute-force       |
| Command timeout                | 120 seconds            | Prevents runaway remote processes      |
| Max output length              | 50,000 bytes           | Caps command output          |
| Max file transfer size         | 10 MiB                 | Prevents disk-fill attacks             |
| Dangerous pattern detection    | Always enabled         | Prevents command injection             |
| Path traversal checks          | 7-layer validation     | Defense-in-depth for SFTP paths        |
| Per-IP rate limiting           | 60 req/min             | Mitigates brute-force and DoS          |
| Max concurrent SSH connections | 20                     | Global cap; excess gets HTTP 503     |
| Non-root container user        | `mcpssh`               | Limits impact of container escape      |
| `--no-cache-dir` in Dockerfile | Enabled                | Reduces image size and attack surface  |

---

## Configuration Hardening

### Secrets Management

- SSH private keys should be mounted as files (Docker secrets or Kubernetes
  secrets), never baked into the image.
- SSH target `password` and API-key `key_hash` values should live in a
  separate `secrets.json` file or `MCP_SSH_SECRET_*` environment variables
  rather than inline in `ssh-mcp-config.json`. Precedence is **env vars >
  `secrets.json` > main config**. See [`lib/secrets.py`](../lib/secrets.py)
  and README §2.8.
- `secrets.json` uses a parallel structure keyed by identifier:

```jsonc
{
  "version": 1,
  "ssh_targets": {
    "<target-id>": { "password": "..." }
  },
  "api_keys": [
    { "name": "<key-name>", "key_hash": "pbkdf2:sha256:..." }
  ]
}
```

- API keys should be hashed before writing. The server provides
  `hash_api_key()` in [`lib/crypto.py`](../lib/crypto.py) for offline
  hashing. `key_hash` is the **only** form stored — never a raw key.
- Env-var mapping: `MCP_SSH_SECRET_PASSWORD_<TARGET_ID>` overrides a target
  password; `MCP_SSH_SECRET_API_KEY_<KEY_NAME>` overrides a `key_hash`.
  Values are hash strings for API keys, not raw keys.

### Error Messages

Config validation messages returned to API clients are sanitized: a
`ConfigValidationError` message never contains raw config values, type names,
CIDRs, or echoed identifiers. Operators get the full path/field via the
structured `field=` attribute; the prose is safe to surface to clients.

### File Permissions

- `ssh-mcp-config.json` should be readable only by the `mcpssh` user
  (`chmod 600`). The server warns (`config.permissions_insecure`) when it is
  more permissive than `0o600`.
- `secrets.json` must not be group/world readable. The server warns
  (`secrets.permissions_insecure`) when it is more permissive than `0o600`.
- The `--fix-permissions` CLI flag auto-corrects both
  `ssh-mcp-config.json` and `secrets.json` to `0o600` on startup, emitting
  `config.permissions_fixed` / `secrets.permissions_fixed` events. Without
  it, the operator must set the mode manually.
- SSH private keys should be readable only by the `mcpssh` user.
- The log directory should be writable by `mcpssh` but not world-readable
  (logs may contain command output and server names).

### Environment Variables

Sensitive values can be injected at runtime:

| Variable          | Purpose                        |
|-------------------|--------------------------------|
| `MCP_SSH_CONFIG_PATH` | Path to configuration directory |
| `MCP_SSH_LOG_DIR`    | Path to log output directory   |
| `MCP_SSH_SSH_KEY`    | Path to SSH private key        |
| `CONFIG_DIR` / `SSH_KEY_PATH` / `LOG_DIR` | Legacy fallbacks for the three above |
| `MAX_OUTPUT_LENGTH` | Max command output length    |
| `MCP_SSH_SETTING_*` | Non-secret `settings` overrides (see below) |
| `MCP_SSH_SECRET_*` | Secrets override (see above) |

`MCP_SSH_SETTING_<KEY>` overrides the `settings` table with the same
precedence as secrets (env vars > `secrets.json` > main config > defaults).
Only keys declared in `SETTING_KEY_TYPES` are accepted; unknown keys and
un-coercible values are ignored with a warning, and the value is never
logged. See [`lib/constants.py`](../lib/constants.py) for the accepted keys.

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
- [Command Security](../lib/command_security.py) — dangerous-pattern and segmentation checks
- [File Transfer Security](../lib/file_transfer.py) — `_validate_path()` with 7-layer checks
- [Authorization Engine](../lib/auth.py) — Layered decision chain
- [Rate Limiter](../lib/rate_limiter.py) — Sliding-window implementation
