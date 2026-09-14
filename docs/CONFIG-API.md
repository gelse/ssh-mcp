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

When enabled, open `http://localhost:9080/api` in your browser to
access the web dashboard (Tailwind CSS SPA). The dashboard provides:

- SSH target management (add, edit, delete, connectivity test)
- Block pattern editor (add, edit, reorder, delete)
- Allowed commands editor (default, API key, network rules)
- Settings editor with validation
- API key hash utility
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

These limitations are acceptable for single-instance deployments.
For multi-instance setups, use Bearer token auth instead of
session cookies.

---

## Security notes

- The `secure` cookie flag defaults to `true` (HTTPS only). Set
  `CONFIG_API_SESSION_COOKIE_SECURE=false` for local HTTP testing.
- The session cookie uses `SameSite=strict` and `HttpOnly`.
- API responses strip secret fields (`password`, `private_key`,
  `key_hash`) before returning config data.
- The maximum request body size is 1 MiB.

See [Security Model](SECURITY.md) for the full threat model.
