# 11a - Separate Secrets, Add Env Var Overrides & Schema Migration

**Parent Plan**: [11-configuration-management.md](plans/11-configuration-management.md)

## Objective
Separate secrets (API keys, SSH passwords) from main config, support environment variable overrides, add schema version migration, and enforce duplicate detection + file permissions.

## Implementation Steps
1. Create `lib/secrets.py` with `SecretsManager`:
   - Loads `secrets.json` if it exists
   - Loads from environment variables: `MCP_SSH_SECRET_*`
   - Merges secrets into config during load
2. Add env var override support to `ConfigManager`:
   - `MCP_SSH_SETTING_*` overrides any setting (e.g., `MCP_SSH_SETTING_MAX_COMMAND_OUTPUT=100kb`)
   - Precedence: env vars > secrets.json > config.json > defaults
3. Create schema migration system in `lib/config_migration.py`:
   - `MIGRATIONS: dict[int, Callable]` mapping version to migration function
   - On load, apply migrations from current version to latest
   - Write migrated config back with `.bak` backup
4. Add duplicate detection to config validation:
   - Check for duplicate target names
   - Check for duplicate API key names
   - Check for overlapping network CIDRs
5. Add file permission enforcement:
   - On config load, `os.stat().st_mode` check for `0o600`
   - Warn if world/group readable
   - Add `--fix-permissions` CLI flag to auto-chmod
6. Expand size unit parsing: support `b`, `kb`, `mb`, `gb` case-insensitively
7. Add `--print-default-config` CLI flag

## Dependencies
- Task 02a (constants), 01c (factory pattern for CLI)

## Acceptance Criteria
- Secrets in separate `secrets.json` or env vars
- Environment variables override any config setting
- Schema migration from v1→v2 works with backup
- Duplicate targets/keys/CIDRs rejected
- File permissions checked with warning
- Size units support b/kb/mb/gb case-insensitively
