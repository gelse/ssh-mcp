# mcp-ssh Examples

Ready-to-use configuration and client examples for the mcp-ssh MCP server.
Everything here uses **placeholder values** (documentation IP addresses,
all-zero API-key hashes) — copy a file, replace the placeholders, and deploy.

## Contents

| File | Purpose |
|---|---|
| [`claude-desktop-config.json`](claude-desktop-config.json) | Claude Desktop MCP server entry (Streamable HTTP + `X-API-Key` header) |
| [`config-basic.json`](config-basic.json) | One SSH target (key auth), default allowlist, standard settings |
| [`config-multi-target.json`](config-multi-target.json) | Two targets (key + password auth), per-API-key command rules |
| [`config-sudo.json`](config-sudo.json) | Rule with `sudo_allowed` — permits selected commands via `sudo=True` |
| [`config-network-auth.json`](config-network-auth.json) | Per-network (CIDR) authorization rules + `trusted_proxies` |
| [`curl-examples.sh`](curl-examples.sh) | Direct JSON-RPC calls for all 6 tools (includes the session handshake) |
| [`mcp-client-example.py`](mcp-client-example.py) | Programmatic client usage with the `fastmcp` library |

## Quick test

With the server running (Docker: `docker compose up`, exposed on host port
9080) and an API key configured:

```bash
export MCP_SSH_API_KEY="your-api-key"

# Full walkthrough of all 6 tools (handles the MCP session handshake):
./curl-examples.sh

# Or a single minimal tools/call:
curl -sS -X POST http://localhost:9080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-API-Key: $MCP_SSH_API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

> The Streamable HTTP transport is **stateful**: before calling tools you
> must obtain a session (`GET /mcp` → `mcp-session-id` response header),
> send `initialize`, then `notifications/initialized`, and pass the
> `Mcp-Session-Id` header on every request. `curl-examples.sh` and the
> Python client do this for you.

## Connecting an MCP client

| Setting | Value |
|---|---|
| Transport | Streamable HTTP |
| URL | `http://localhost:9080/mcp` (Docker; container listens on `8080`) |
| Authentication | `X-API-Key` header or `Authorization: Bearer` |

For Claude Desktop, copy [`claude-desktop-config.json`](claude-desktop-config.json)
into your `claude_desktop_config.json` (Settings → Developer → Edit Config)
and replace the API key placeholder.

For a programmatic client, see [`mcp-client-example.py`](mcp-client-example.py):

```bash
pip install fastmcp
export MCP_SSH_API_KEY="your-api-key"
python mcp-client-example.py
```

## Using the example configs

Mount a config as `/config/ssh-mcp-config.json` in the container
(`docker compose` mounts `./config/` by default):

```bash
cp examples/config-basic.json config/ssh-mcp-config.json
docker compose up -d
```

### Things to replace

| Placeholder | Where | Replace with |
|---|---|---|
| `192.0.2.x` hosts | all configs | Your real SSH hostnames/IPs |
| `/app/ssh_key` | key-auth targets | Path to the private key **inside the container** |
| `REPLACE_ME_OR_USE_SECRETS_JSON` | `config-multi-target.json` | Prefer `secrets.json` or `MCP_SSH_SECRET_PASSWORD_DB_SERVER` over inline passwords |
| `sha256:0000…0000` | `config-multi-target.json` | A real API-key hash (see below) |
| `REPLACE_WITH_YOUR_API_KEY` | `claude-desktop-config.json` | The raw API key your client sends |
| `172.18.0.1` | `config-network-auth.json` | Your reverse-proxy IP(s) if behind Traefik/nginx |

### Generating an API-key hash

Config files never contain raw API keys — only hashes. Generate one with the
Config API dashboard (hash utility) or directly:

```bash
docker compose exec ssh-mcp python -c \
  "from lib.crypto import hash_api_key; print(hash_api_key('your-api-key'))"
# → pbkdf2:sha256:100000$<salt>$<hash>
```

Alternatively, keep the hash out of the main config entirely via
`secrets.json` or the `MCP_SSH_SECRET_API_KEY_<KEY_NAME>` environment
variable (name upper-cased, `-` → `_`; e.g. key `ci-bot` →
`MCP_SSH_SECRET_API_KEY_CI_BOT`). See the
[Secrets section](../README.md#secrets) in the main README.

### Notes on specific configs

- **`config-sudo.json`** — `sudo` is never typed into commands (the
  `block_patterns` deny the literal word `sudo`). Instead, call
  `ssh_execute_command` with `"sudo": true`; the command itself must be
  listed in the rule's `commands` **and** its `sudo_allowed` list.
  The target's SSH user needs passwordless sudo for those commands.
- **`config-network-auth.json`** — network rules match the client source IP.
  Behind a reverse proxy, set `trusted_proxies` to the proxy IPs so the
  `X-Forwarded-For` header is honored; otherwise the proxy's IP is matched.
- Rate limiting defaults to 60 requests/minute per IP — tune via
  `settings.rate_limit` if your client is chattier.

## Security reminders

- Never commit real API keys, passwords, or private key material — the
  placeholders here exist so nothing sensitive leaks by copy-paste.
- `key_hash` is the only form in which API keys are stored; raw keys live
  only in your client configuration.
- Upload paths must start with `/tmp/` or `/home/`; downloads/commands are
  constrained by the layered authorization chain (`block_patterns` →
  dangerous-pattern guards → default → api-key → network rules). See
  [`docs/SECURITY.md`](../docs/SECURITY.md) for the full model.
