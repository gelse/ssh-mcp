# Config API & Dashboard

The Config API is an optional FastAPI service mounted alongside the
MCP server. It provides a REST API and a web dashboard for managing
configuration without editing JSON files directly.

---

## Enabling

Set these environment variables (see [`compose.yaml`](../compose.yaml)):

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_API_ENABLED` | `false` | Enable the Config API |
| `CONFIG_API_TOKEN` | `""` | Bearer token for API authentication |
| `CONFIG_API_SESSION_COOKIE_SECURE` | `true` | Restrict session cookie to HTTPS |

Example `compose.yaml` override:

```yaml
environment:
  - CONFIG_API_ENABLED=true
  - CONFIG_API_TOKEN=my-secret-token
  - CONFIG_API_SESSION_COOKIE_SECURE=false
```

The API is served on the same port as the MCP server (8080) under
the `/api` prefix.

---

## Dashboard

When enabled, open `http://localhost:9080/api/ui/` in your browser to
access the web dashboard (Tailwind CSS SPA). The API's own interactive docs
are at `/api/docs`. The dashboard provides:

- SSH target management (add, edit, delete, connectivity test, sudoers
  file generation)
- Block pattern editor (add, edit, reorder, delete)
- Allowed commands editor (default, API key, network rules)
- Settings editor with validation
- API key creation — the server generates the key, returns it once, and stores only its hash
- Backup management (list, restore, delete)
- Config validation (dry-run)

---

## Authentication

Two auth methods are supported:

1. **Bearer token** — Pass `Authorization: Bearer <token>` header
   on every request. The token is compared with timing-safe
   `hmac.compare_digest`.

2. **Session cookie** — POST to `/api/auth/login` with
   `{"token": "<raw_token>"}`. On success, an HttpOnly session
   cookie is set. Subsequent requests use the cookie automatically.

Sessions are in-memory and expire after **3600 seconds** (max age)
or **1800 seconds** of idle time.

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | no | Create session cookie |
| POST | `/api/auth/logout` | yes | Revoke session, clear cookie |
| GET | `/api/auth/session` | yes | Check session validity |

---

## Endpoint reference

### Health & schema (no auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Liveness probe |
| GET | `/api/config/schema` | Return config JSON Schema |

### Config (requires auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/config` | Read full config (secrets stripped) |
| PUT | `/api/config` | Replace full config |
| GET | `/api/config/{section}` | Read single section |
| PUT | `/api/config/{section}` | Replace single section |

Valid sections: `ssh_targets`, `block_patterns`,
`allowed_commands`, `settings`.

### SSH targets (requires auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/config/ssh_targets/{name}` | Read target (secrets stripped) |
| PUT | `/api/config/ssh_targets/{name}` | Create or replace target |
| DELETE | `/api/config/ssh_targets/{name}` | Delete target |
| POST | `/api/config/ssh_targets/{name}/check` | Test SSH connectivity |
| GET | `/api/config/ssh_targets/{name}/sudoers` | Generate a sudoers drop-in from the target's sudo grants |

`{name}` is a target id — the same value MCP tools take as `server_name`.

Credentials are never returned: a target read carries `has_password` and
`has_private_key` instead, so the dashboard can show what is stored without
seeing it.

`PUT` is read-modify-write for secrets. A missing or empty `password` /
`private_key` keeps the stored value, an explicit `null` deletes it, and a
new value replaces it:

```json
{"host": "10.42.43.13", "port": 22, "username": "werner", "password": null}
```

Deleting the last credential is rejected with 400 — the config needs at
least one of `password` or `private_key` per target. In the dashboard, the
Edit dialog offers a *Remove the stored password* checkbox directly under
the password field, and the same for the key, whenever the server reports
one is stored; when nothing is stored the field says so instead
(*No password stored*).

#### Sudoers generation

`GET /api/config/ssh_targets/{name}/sudoers` builds a
`/etc/sudoers.d` drop-in for one target, so `sudo=True` works on that host
without editing sudoers by hand.

- **Scope** — the union of every rule layer that applies to the target:
  `default`, API-key and network rules. Each rule contributes only the
  commands named in its own `sudo_allowed`, because all three layers log
  in as the target's single `username`.
- **Layout** — one grant line, no aliases:
  `username ALL = (root) NOPASSWD: /usr/bin/a, /usr/bin/b, …`. The
  Host field is always `ALL`: sudo compares it against the local machine
  name and never matches an address, and the file only applies on the
  machine it is installed on. sudoers has no line-continuation character,
  so the line stays one line however many commands it holds.
- **Arguments** — each entry is a bare absolute path, with no argument
  pattern. A command specification without a pattern permits any
  arguments, which matches what the rule means (it names the base command
  only) — so a grant for `docker` is root-equivalent for that binary,
  which the rule already allows. A trailing `*` would mean the same to
  classic sudo but is not implemented by sudo-rs before 0.2.9 (Ubuntu
  25.10), where it makes the entry match nothing at all.
- **Paths** — resolved live on the target over SSH (`command -v`, with a
  `PATH` scan fallback for shell builtins), so they match what the server
  executes. The target must be reachable.
- **Unresolved commands** — commented out in the file and listed in the
  dialog. A rule with `commands: ["*"]` and `sudo_allowed: ["*"]` is
  skipped and reported: the file never grants `ALL`.
- **Empty result** — when no command resolves, `content` is empty and
  `notes` explain why, so the dashboard can show the reason instead of an
  unusable file.

The response carries `target`, `username`, `host`, `filename`,
`content`, `resolved`, `unresolved`, `skipped`, `invalid` and `notes`.
Path resolution needs direct SSH access: in a deployment where the config
API reaches the MCP server over HTTP only, every command is reported as
unresolved and no file is produced.

Unknown target → 404; unreachable target → 502.

### API keys (requires auth)

API keys are written one entry at a time. The key hash never leaves the
server, so a section PUT that round-trips the whole `api_keys` array
cannot work and is rejected.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/config/api_keys` | Create a key from `{"name", "target"}`; the secret is generated server-side and returned once, with `ls` allowed on the target |
| PUT | `/api/config/api_keys/{name}` | Replace that key's rules with `{"rules": [...]}` |
| DELETE | `/api/config/api_keys/{name}` | Delete the key |

The name identifies the entry and cannot be changed, `key_hash` is never
returned, and every write goes through full config validation. A
`PUT /api/config/allowed_commands` body containing `api_keys` is
rejected with 400; write `default` and `networks` there, and keys through
the endpoints above.

### Block patterns (requires auth)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/config/block_patterns` | Append pattern |
| PUT | `/api/config/block_patterns` | Replace all patterns |
| PUT | `/api/config/block_patterns/{index}` | Replace single pattern |
| DELETE | `/api/config/block_patterns/{index}` | Remove single pattern |

### Backups (requires auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/backups` | List backup files |
| POST | `/api/backups/{name}/restore` | Restore from backup |
| DELETE | `/api/backups/{name}` | Delete a backup |

### Hash utility (requires auth)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/hash-key` | Hash a plaintext API key (PBKDF2) |

---

## Session limitations

- **In-memory** — sessions are not persisted to disk
- **Single-instance** — not shared across multiple containers
- **Lost on restart** — clients must re-authenticate after restart
- **Max age** — 3600 seconds hard expiry
- **Idle timeout** — 1800 seconds of inactivity

These limitations apply only to **dashboard login sessions** —
configuration changes made via the API are always persisted to the
config file normally. These limitations are acceptable for
single-instance deployments. For multi-instance setups, use Bearer
token auth instead of session cookies.

---

## Security notes

- The `secure` cookie flag defaults to `true` (HTTPS only). Set
  `CONFIG_API_SESSION_COOKIE_SECURE=false` for local HTTP testing.
- The session cookie uses `SameSite=strict` and `HttpOnly`.
- API responses strip secret fields (`password`, `private_key`,
  `key_hash`) before returning config data.
- The maximum request body size is 1 MiB.

See [Security Model](SECURITY.md) for the full threat model.
