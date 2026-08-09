# 11 - Configuration Management

## Current State Analysis

### Config Architecture

[`lib/config.py`](lib/config.py:1) implements `ConfigManager` with:
- JSON file loading from configurable path
- Strict schema validation with `ConfigValidationError`
- Default config creation if file doesn't exist
- Hot-reload via background watcher thread (mtime polling, 15s interval)
- Thread-safe access via `threading.Lock`

### Config Schema (from [`default-config.json`](default-config.json:1))
```json
{
  "version": 1,
  "ssh_targets": [
    {
      "name": "...",
      "host": "...",
      "username": "...",
      "port": 22,
      "auth": { "type": "key", "key_filename": "..." }
        // or { "type": "password", "password": "..." }
      "sudo_allowed": false
    }
  ],
  "block_patterns": ["pattern1", "pattern2", ...],
  "allowed_commands": {
    "default": ["cmd1", "cmd2", ...],
    "api_keys": {
      "key_name": { "commands": [...], "description": "..." }
    },
    "networks": {
      "192.168.1.0/24": { "commands": [...], "description": "..." }
    }
  },
  "settings": {
    "max_command_output": "50kb",
    "command_timeout_seconds": 120,
    "log_file": "ssh-executions.log",
    "max_log_file_size_mb": 10,
    "max_log_backup_count": 5,
    "watcher_interval_seconds": 15
  },
  "api_keys": {
    "monitoring-service": "sha256:abc123...",
    "full-admin": "sha256:def456..."
  }
}
```

### Issues Identified

#### 1. Passwords in Config
SSH target passwords are stored in plaintext in [`default-config.json`](default-config.json:1) under `auth.password`. This is a security risk:
- Config file permissions not enforced programmatically
- Config may be committed to version control accidentally
- Password visible in logs if config is logged

#### 2. API Keys in Same Config File
API key hashes live alongside target definitions. An operator editing targets could accidentally modify or leak key hashes. Separate secrets management would be better.

#### 3. Config File Permissions Not Enforced
No check that config file has restricted permissions (e.g., `0o600`). On systems with lax umask, config could be world-readable.

#### 4. No Environment Variable Overrides
All configuration must come from the JSON file. Common operational patterns (Docker Compose, Kubernetes) prefer env var overrides for:
- SSH key paths
- Log directory
- Individual settings

#### 5. No Validation for Duplicate Target Names
Two targets with the same `name` field would silently shadow each other. The last one in the list wins.

#### 6. Size Unit Parsing
`max_command_output: "50kb"` uses custom string parsing. This is fine but:
- Only supports `kb` unit
- No validation that value is positive
- Case sensitivity not documented (`50KB` vs `50kb` vs `50Kb`)

#### 7. No Config Schema Version Migration
The `version: 1` field is present but no migration logic exists. If the schema changes in v2, old configs will fail validation with unhelpful errors.

#### 8. Watcher Debounce Missing
If the config file is written in multiple chunks (e.g., `rsync`, editor save), the watcher may trigger multiple reloads. No debounce or cooldown.

#### 9. No Config Reload Notification
When config reloads, tools continue using stale references until they call `config_manager.get_target()` again. No event/callback mechanism to notify dependent components.

#### 10. Config Validation Error Messages
[`ConfigValidationError`](lib/config.py:1) tracks error fields but error messages may expose file paths or internal structure. Error messages should be safe to return to API clients.

### Configuration Improvements

1. **Separate Secrets from Config**
   - Move `api_keys` and `auth.password` to a separate `secrets.json` file
   - `secrets.json` permissions enforced to `0o600`
   - Or support environment variables: `SSH_TARGET_MYSERVER_PASSWORD=...`
   - Or support Docker secrets: `/run/secrets/mcp-ssh/...`

2. **Environment Variable Overrides**
   - Support `MCP_SSH_CONFIG_PATH`, `MCP_SSH_LOG_DIR`, `MCP_SSH_SSH_KEY`
   - Support `MCP_SSH_SETTING_MAX_COMMAND_OUTPUT` etc.
   - Precedence: env vars > config file > defaults

3. **Schema Migration System**
   - On load, check `version` field
   - Apply migration functions: `v1→v2`, `v2→v3`
   - Warn on unknown version
   - Write migrated config back (with backup)

4. **Duplicate Detection**
   - Validate no duplicate target names
   - Validate no duplicate API key names
   - Validate no overlapping network CIDRs

5. **File Permission Enforcement**
   - On config load, check file mode
   - Warn if config is world/group-readable
   - Optionally auto-fix (`chmod 0o600`)

6. **Watcher Improvements**
   - Add debounce: ignore changes within N seconds of last reload
   - Add notification callback for config consumers
   - Add `on_config_change(callback)` registration

7. **Size Unit Expansion**
   - Support `b`, `kb`, `mb`, `gb`
   - Case-insensitive parsing
   - Clear error on invalid format

8. **Config Documentation Generation**
   - Add `--print-default-config` CLI flag
   - Generate JSON Schema for IDE autocompletion
   - Add comments to default-config.json (or separate schema doc)

### Acceptance Criteria
- Secrets separated from main config (secrets.json or env vars)
- Environment variables can override any config setting
- Schema version migration system functional
- Duplicate target names rejected with clear error
- File permissions checked on load
- Watcher has debounce to prevent rapid reloads
- Config changes notify dependent components
- Size units support b/kb/mb/gb case-insensitively
