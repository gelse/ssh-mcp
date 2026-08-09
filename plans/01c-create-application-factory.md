# 01c - Create Application Factory & Dependency Injection

**Parent Plan**: [01-clean-architecture.md](plans/01-clean-architecture.md)

## Objective
Replace the global FastMCP instance and module-level state in [`server.py`](server.py:1) with an application factory pattern that supports dependency injection.

## Context
Currently, `mcp`, `config_manager`, `auth_manager`, and `logger` are module-level globals. This makes testing difficult and couples the entire application. Tools access these globals directly rather than through injection.

## Implementation Steps

1. Create `create_app()` factory function in `server.py`:
   ```python
   def create_app(
       config_path: str | Path,
       log_dir: str | Path,
       ssh_key_path: str | Path | None = None,
   ) -> FastMCP:
   ```

2. Inside factory, initialize all components:
   - `ConfigManager(config_path)` with watcher startup
   - `AuthorizationManager(config_manager.get_full_config())`
   - `FileLogger(log_dir, config_manager.get_settings())`
   - `SSHClientManager(ssh_key_path)`
   - `FileTransferService(ssh_client_manager)`

3. Register config reload callback:
   - When config reloads, call `auth_manager.update_rules(new_config)`
   - When config reloads, call `logger.update_settings(new_settings)`

4. Define tool functions to accept dependencies via closure:
   ```python
   def register_tools(mcp, services):
       ssh_client_mgr = services["ssh_client_manager"]
       file_transfer_svc = services["file_transfer_service"]
       # ... register tools with closures capturing services
   ```

5. Keep module-level `if __name__ == "__main__"` that calls `create_app()` using env vars for paths.

6. Add `--config`, `--log-dir`, `--ssh-key` CLI arguments using argparse.

## Dependencies
- Task 01a (SSHClientManager)
- Task 01b (FileTransferService)

## Acceptance Criteria
- `create_app()` function returns configured FastMCP instance
- No module-level globals for core components
- Tools receive dependencies via closure, not global access
- Tests can instantiate app with mock dependencies
- CLI supports `--config`, `--log-dir`, `--ssh-key` flags
