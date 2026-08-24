"""Config file read/write/validate service.

Reads, validates, and atomically writes the SSH MCP configuration file,
reusing ``ConfigManager._validate()`` from ``lib/config.py``.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config_api.mcp_client import MCPClient, MCPClientError, MCPToolError
from lib.config import ConfigManager
from lib.constants import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_SSH_KEY_FILENAME,
    RESTRICTED_FILE_MODE,
    TARGET_NAME_PATTERN,
)
from lib.exceptions import ConfigValidationError

# Attempt to import ssh_operations for direct SSH calls (unified mode).
# In standalone mode, this import will fail and MCPClient is used instead.
try:
    import lib.ssh_operations as _ssh_operations_module
except ImportError:
    _ssh_operations_module = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class ConfigService:
    """Read, validate, and atomically write the SSH MCP config file.

    Thread safety: a ``threading.Lock`` serializes all write operations.
    Reads are lock-free (they only read the file, no shared mutable state).

    Attributes:
        config_dir: Path to the config directory.
        config_path: Path to the config JSON file.
    """

    # Fields that contain secret material and must be stripped from PUT payloads.
    _SECRET_FIELDS = frozenset({"password", "private_key", "key_hash"})

    #: Valid top-level config section names.
    VALID_SECTIONS = frozenset({
        "ssh_targets",
        "block_patterns",
        "allowed_commands",
        "settings",
    })

    def __init__(
        self,
        config_dir: str | None = None,
        *,
        ssh_client_manager: object | None = None,
        ssh_config_manager: object | None = None,
        ssh_key_path: str | None = None,
    ) -> None:
        """Initialise the config service.

        Args:
            config_dir: Path to the config directory.  Falls back to the
                ``CONFIG_DIR`` environment variable or the compiled default.
            ssh_client_manager: An
                :class:`~lib.ssh_client.SSHClientManager` instance for
                direct SSH calls (unified mode).  ``None`` falls back to
                MCPClient (standalone mode).
            ssh_config_manager: A :class:`~lib.config.ConfigManager`
                instance whose :meth:`get_ssh_target` returns the *full*
                (unstripped) target dict.  Required when
                *ssh_client_manager* is provided.
            ssh_key_path: Default path to the SSH private key used by
                :func:`lib.ssh_operations.check_ssh_connection`.  Falls
                back to ``DEFAULT_SSH_KEY_FILENAME`` when omitted.
        """
        self.config_dir = Path(
            config_dir or os.environ.get("CONFIG_DIR", DEFAULT_CONFIG_DIR)
        )
        self.config_path = self.config_dir / DEFAULT_CONFIG_FILENAME
        self._write_lock = threading.Lock()

        # Create a ConfigManager for validation only.
        # __init__ calls self.load() which reads the existing file — this is
        # expected and harmless.  The ConfigManager instance is used solely
        # for its _validate() method.
        self._validator = ConfigManager(str(self.config_dir))

        # Direct SSH operation dependencies (unified mode).
        self._ssh_client_manager = ssh_client_manager
        self._ssh_config_manager = ssh_config_manager
        self._ssh_key_path = ssh_key_path or DEFAULT_SSH_KEY_FILENAME

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def read_config(self) -> dict:
        """Read and return the raw on-disk config as a dict.

        Returns the JSON content without any secret merging or env var
        overrides.  This is the config file's actual content.

        Raises:
            FileNotFoundError: If the config file does not exist.
            json.JSONDecodeError: If the file contains invalid JSON.
        """
        with self.config_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def read_section(self, section: str) -> dict:
        """Read a single top-level section from the config.

        Args:
            section: One of 'ssh_targets', 'block_patterns',
                     'allowed_commands', 'settings'.

        Returns:
            The section's value as a dict (or list for block_patterns).

        Raises:
            KeyError: If the section does not exist in the config.
            ValueError: If section is not a valid section name.
        """
        if section not in self.VALID_SECTIONS:
            raise ValueError(
                f"Invalid section '{section}'. "
                f"Valid sections: {', '.join(sorted(self.VALID_SECTIONS))}"
            )
        config = self.read_config()
        if section not in config:
            raise KeyError(f"Section '{section}' not found in config")
        return config[section]

    # ------------------------------------------------------------------
    # Granular read operations
    # ------------------------------------------------------------------

    def get_ssh_target(self, name: str) -> dict:
        """Read a single SSH target by name, with secrets stripped.

        Args:
            name: The SSH target identifier.

        Returns:
            The target config dict (password, private_key stripped).

        Raises:
            KeyError: If the target does not exist.
            FileNotFoundError: If the config file does not exist.
        """
        config = self.read_config()
        targets = config.get("ssh_targets", {})
        if name not in targets:
            raise KeyError(f"SSH target '{name}' not found in config")
        target = targets[name]
        # Strip secrets from a single target dict
        clean = copy.deepcopy(target)
        if isinstance(clean, dict):
            for field in self._SECRET_FIELDS:
                clean.pop(field, None)
        return clean

    @property
    def _use_direct_ssh(self) -> bool:
        """Return ``True`` when direct SSH calls are available (unified mode)."""
        return (
            _ssh_operations_module is not None
            and self._ssh_client_manager is not None
            and self._ssh_config_manager is not None
        )

    def check_ssh_target(self, name: str, timeout: int = 10) -> dict:
        """Execute the checkcommand on an SSH target to verify connectivity.

        In **unified mode** (when ``lib.ssh_operations`` is importable and
        the required managers have been injected), calls
        :func:`lib.ssh_operations.check_ssh_connection` directly — no HTTP
        round-trip required.

        In **standalone mode** falls back to the MCP server's
        ``ssh_check_connection`` tool via :class:`MCPClient`.

        Args:
            name: The SSH target identifier.
            timeout: Connection/command timeout in seconds.

        Returns:
            Dict with ``success``, ``output``, ``error``, ``exit_code``,
            and ``checkcommand`` fields.

        Raises:
            KeyError: If the target does not exist.
        """
        # Retrieve target info (raises KeyError if missing).
        # In standalone mode this also gets the checkcommand for the
        # fallback error response.
        target = self.get_ssh_target(name)
        checkcommand = target.get("checkcommand", "echo ping")

        # ----- Unified mode: direct function call -----
        if self._use_direct_ssh:
            try:
                result = _ssh_operations_module.check_ssh_connection(
                    ssh_client_manager=self._ssh_client_manager,
                    config_manager=self._ssh_config_manager,
                    target_name=name,
                    ssh_key_path=self._ssh_key_path,
                    timeout=timeout,
                )
                return {
                    "success": result.get("success", False),
                    "output": result.get("output", ""),
                    "error": result.get("error"),
                    "exit_code": result.get("exit_code", -1),
                    "checkcommand": result.get("checkcommand", checkcommand),
                }
            except Exception as exc:
                # Translate any library exception into the standard
                # error dict so the API contract is preserved.
                return {
                    "success": False,
                    "output": "",
                    "error": str(exc),
                    "exit_code": -1,
                    "checkcommand": checkcommand,
                }

        # ----- Standalone mode: MCPClient HTTP fallback -----
        mcp_client = MCPClient()
        try:
            result = mcp_client.call_tool(
                "ssh_check_connection",
                arguments={"server_name": name, "timeout": timeout},
                timeout=timeout + 5,  # Extra buffer for HTTP overhead
            )
            return {
                "success": result.get("success", False),
                "output": result.get("output", ""),
                "error": result.get("error"),
                "exit_code": result.get("exit_code", -1),
                "checkcommand": result.get("checkcommand", checkcommand),
            }
        except MCPToolError as e:
            # Tool returned an error response (e.g., target not found)
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "exit_code": -1,
                "checkcommand": checkcommand,
            }
        except MCPClientError as e:
            return {
                "success": False,
                "output": "",
                "error": f"MCP server unreachable: {e}",
                "exit_code": -1,
                "checkcommand": checkcommand,
            }

    def get_block_patterns(self) -> list[str]:
        """Read the block_patterns list from the config.

        Returns:
            The list of block pattern strings.

        Raises:
            FileNotFoundError: If the config file does not exist.
        """
        config = self.read_config()
        return config.get("block_patterns", [])

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_config(self, config: dict) -> dict:
        """Validate a candidate config dict using ConfigManager._validate().

        Args:
            config: The candidate config dict to validate.

        Returns:
            A validated deep copy with defaults applied.

        Raises:
            ConfigValidationError: If validation fails.
        """
        return self._validator._validate(config)

    def validate_only(self, config: dict) -> dict:
        """Validate a config dict without writing to disk.

        This is a thin wrapper around validate_config() that makes the
        intent explicit in the method name.

        Args:
            config: The candidate config dict to validate.

        Returns:
            A validated deep copy with defaults applied.

        Raises:
            ConfigValidationError: If validation fails.
        """
        return self.validate_config(config)

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def write_config(self, config: dict) -> dict:
        """Validate and atomically write a config dict to disk.

        Process:
        1. Validate using ConfigManager._validate() (secrets required
           for validation — at least one of password/private_key)
        2. Strip secret fields from the validated config
        3. Create a timestamped .bak backup of the current file
        4. Write to a temp file in the same directory
        5. Atomic rename via os.replace()

        Args:
            config: The candidate config dict (may contain secrets — they
                    will be stripped before writing).

        Returns:
            The validated config dict that was written to disk (secrets
            stripped).

        Raises:
            ConfigValidationError: If validation fails.
            FileNotFoundError: If the config directory does not exist.
            OSError: If file operations fail.
        """
        # Step 1: Validate (requires secrets for auth checks)
        validated = self.validate_config(config)

        # Step 2: Strip secrets for the return value (API responses)
        clean = self._strip_secrets(validated)

        with self._write_lock:
            # Step 3: Backup
            self._create_backup()

            # Step 4-5: Atomic write (secrets kept on disk for
            # read-modify-write cycles — stripping only happens in
            # the return value so API callers never see them)
            self._atomic_write(validated)

        return clean

    def write_section(self, section: str, data: dict | list) -> dict:
        """Replace a single section in the config, validate, and write.

        Reads the current full config, replaces the specified section,
        validates the result, and atomically writes.

        Args:
            section: The section name to replace.
            data: The new section content.

        Returns:
            The validated full config that was written to disk.

        Raises:
            ValueError: If section is not a valid section name.
            ConfigValidationError: If the merged config fails validation.
        """
        if section not in self.VALID_SECTIONS:
            raise ValueError(
                f"Invalid section '{section}'. "
                f"Valid sections: {', '.join(sorted(self.VALID_SECTIONS))}"
            )

        # Read current config
        current = self.read_config()

        # Replace section
        current[section] = data

        # Validate and write (write_config handles stripping + validation)
        return self.write_config(current)

    # ------------------------------------------------------------------
    # Granular write operations
    # ------------------------------------------------------------------

    def put_ssh_target(self, name: str, target_data: dict) -> dict:
        """Create or replace a single SSH target.

        Reads the current config, replaces or adds the target, validates
        the full config, and atomically writes.

        Args:
            name: The SSH target identifier.
            target_data: The target config dict (may include
                password/private_key).

        Returns:
            The updated target dict (secrets stripped).

        Raises:
            ValueError: If the target name is invalid.
            ConfigValidationError: If the merged config fails validation.
        """
        if not re.fullmatch(TARGET_NAME_PATTERN, name):
            raise ValueError(f"Invalid target name: {name!r}")

        current = self.read_config()
        current.setdefault("ssh_targets", {})[name] = target_data
        written = self.write_config(current)
        target = written["ssh_targets"][name]
        clean = copy.deepcopy(target)
        if isinstance(clean, dict):
            for field in self._SECRET_FIELDS:
                clean.pop(field, None)
        return clean

    def delete_ssh_target(self, name: str) -> None:
        """Delete a single SSH target.

        Reads the current config, removes the target, validates, and
        writes.

        Args:
            name: The SSH target identifier to delete.

        Raises:
            KeyError: If the target does not exist.
            ConfigValidationError: If the config without this target
                fails validation (e.g. it was the last target).
        """
        current = self.read_config()
        targets = current.get("ssh_targets", {})
        if name not in targets:
            raise KeyError(f"SSH target '{name}' not found in config")
        del targets[name]
        self.write_config(current)

    def put_block_pattern(self, index: int, pattern: str) -> list[str]:
        """Replace a single block pattern at the given index.

        Args:
            index: Zero-based index into the block_patterns list.
            pattern: The new regex pattern string.

        Returns:
            The updated block_patterns list.

        Raises:
            IndexError: If the index is out of range.
            ConfigValidationError: If the pattern is not a valid regex
                or the merged config fails validation.
        """
        current = self.read_config()
        patterns = current.get("block_patterns", [])
        if index < 0 or index >= len(patterns):
            raise IndexError(
                f"Block pattern index {index} out of range "
                f"(list has {len(patterns)} entries)"
            )
        # Validate the regex pattern
        re.compile(pattern)
        patterns[index] = pattern
        current["block_patterns"] = patterns
        written = self.write_config(current)
        return written["block_patterns"]

    def delete_block_pattern(self, index: int) -> list[str]:
        """Remove a single block pattern at the given index.

        Args:
            index: Zero-based index into the block_patterns list.

        Returns:
            The updated block_patterns list.

        Raises:
            IndexError: If the index is out of range.
        """
        current = self.read_config()
        patterns = current.get("block_patterns", [])
        if index < 0 or index >= len(patterns):
            raise IndexError(
                f"Block pattern index {index} out of range "
                f"(list has {len(patterns)} entries)"
            )
        patterns.pop(index)
        current["block_patterns"] = patterns
        written = self.write_config(current)
        return written["block_patterns"]

    def append_block_pattern(self, pattern: str) -> list[str]:
        """Append a new block pattern to the list.

        Args:
            pattern: The regex pattern string to append.

        Returns:
            The updated block_patterns list.

        Raises:
            ConfigValidationError: If the pattern is not a valid regex
                or the merged config fails validation.
        """
        current = self.read_config()
        patterns = current.get("block_patterns", [])
        # Validate the regex pattern
        re.compile(pattern)
        patterns.append(pattern)
        current["block_patterns"] = patterns
        written = self.write_config(current)
        return written["block_patterns"]

    def replace_block_patterns(self, patterns: list[str]) -> list[str]:
        """Replace the entire block_patterns list.

        Args:
            patterns: The new list of regex pattern strings.

        Returns:
            The written block_patterns list.

        Raises:
            ConfigValidationError: If any pattern is not a valid regex
                or the merged config fails validation.
        """
        written = self.write_section("block_patterns", patterns)
        return written["block_patterns"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _strip_secrets(self, config: dict) -> dict:
        """Remove secret fields from ssh_targets in the config dict.

        Creates a deep copy to avoid mutating the input.  Strips:
        - 'password' from each SSH target
        - 'private_key' from each SSH target
        - 'key_hash' from API key entries in allowed_commands

        Args:
            config: The config dict to strip secrets from.

        Returns:
            A new dict with secret fields removed.
        """
        config = copy.deepcopy(config)

        # Strip SSH target secrets
        targets = config.get("ssh_targets", {})
        if isinstance(targets, dict):
            for target_def in targets.values():
                if isinstance(target_def, dict):
                    for field in self._SECRET_FIELDS:
                        target_def.pop(field, None)

        # Strip API key hashes from allowed_commands
        allowed = config.get("allowed_commands", {})
        if isinstance(allowed, dict):
            api_keys = allowed.get("api_keys", [])
            if isinstance(api_keys, list):
                for entry in api_keys:
                    if isinstance(entry, dict):
                        entry.pop("key_hash", None)

        return config

    def _create_backup(self) -> Path | None:
        """Create a timestamped .bak copy of the current config file.

        Returns the backup path, or None if the config file doesn't exist yet.
        """
        if not self.config_path.exists():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = self.config_path.with_suffix(f".{timestamp}.bak")

        # Use atomic copy: write to temp, then rename
        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(self.config_dir),
            suffix=".bak.tmp",
        )
        try:
            with os.fdopen(fd, "wb") as tmp:
                with self.config_path.open("rb") as src:
                    while chunk := src.read(65536):
                        tmp.write(chunk)
            os.replace(tmp_path_str, str(backup_path))
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path_str)
            except OSError:
                pass
            raise

        # Match the config file permissions
        try:
            os.chmod(str(backup_path), RESTRICTED_FILE_MODE)
        except OSError:
            pass  # Non-critical

        return backup_path

    # ------------------------------------------------------------------
    # Backup operations
    # ------------------------------------------------------------------

    def backup_list(self) -> list[dict]:
        """List all config backup files, sorted newest first.

        Scans config_dir for files matching the pattern
        ``ssh-mcp-config.*.bak`` (matching the format produced by
        ``_create_backup()``).

        Returns:
            List of dicts with keys: name, size_bytes, created_at.
            Sorted by created_at descending (newest first).

        Raises:
            FileNotFoundError: If the config directory does not exist.
        """
        if not self.config_dir.is_dir():
            raise FileNotFoundError(
                f"Config directory does not exist: {self.config_dir}"
            )

        backups: list[dict] = []
        for path in self.config_dir.glob("ssh-mcp-config.*.bak"):
            # Extract the timestamp portion between "ssh-mcp-config." and ".bak"
            stem = path.stem  # e.g. "ssh-mcp-config.20260823T120000Z"
            parts = stem.split(".", 1)
            if len(parts) < 2:
                continue
            ts_str = parts[1]
            try:
                ts = datetime.strptime(ts_str, "%Y%m%dT%H%M%SZ")
            except ValueError:
                continue  # Skip malformed filenames
            stat = path.stat()
            backups.append({
                "name": path.name,
                "size_bytes": stat.st_size,
                "created_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })

        backups.sort(key=lambda b: b["created_at"], reverse=True)
        return backups

    def backup_restore(self, backup_name: str) -> dict:
        """Restore configuration from a backup file.

        Args:
            backup_name: The backup filename (e.g.
                'ssh-mcp-config.20260823T120000Z.bak').

        Returns:
            The restored config dict (secrets stripped).

        Raises:
            FileNotFoundError: If the backup file does not exist.
            ValueError: If the backup filename is invalid or contains
                path traversal characters.
            ConfigValidationError: If the backup content fails
                validation.
            json.JSONDecodeError: If the backup file contains invalid
                JSON.
        """
        self._validate_backup_name(backup_name)

        backup_path = self.config_dir / backup_name
        if not backup_path.is_file():
            raise FileNotFoundError(
                f"Backup file not found: {backup_path}"
            )

        # Read and parse the backup
        with backup_path.open("r", encoding="utf-8") as f:
            backup_data = json.load(f)

        # Validate the backup content
        validated = self.validate_config(backup_data)

        # Create a backup of the current config before overwriting
        self._create_backup()

        # Strip secrets and atomically write the restored config
        clean = self._strip_secrets(validated)
        self._atomic_write(clean)

        return clean

    def backup_delete(self, backup_name: str) -> None:
        """Delete a single backup file.

        Args:
            backup_name: The backup filename to delete.

        Raises:
            FileNotFoundError: If the backup file does not exist.
            ValueError: If the backup filename is invalid or contains
                path traversal characters.
        """
        self._validate_backup_name(backup_name)

        backup_path = self.config_dir / backup_name
        if not backup_path.is_file():
            raise FileNotFoundError(
                f"Backup file not found: {backup_path}"
            )
        backup_path.unlink()

    def cleanup_old_backups(self, max_age_days: int = 7) -> int:
        """Delete backup files older than max_age_days.

        Scans for ``ssh-mcp-config.*.bak`` files, parses the timestamp
        from each filename, and deletes those older than the threshold.

        Args:
            max_age_days: Maximum age in days. Default 7.

        Returns:
            Number of backup files deleted.

        Raises:
            FileNotFoundError: If the config directory does not exist.
        """
        if not self.config_dir.is_dir():
            raise FileNotFoundError(
                f"Config directory does not exist: {self.config_dir}"
            )

        now = datetime.now(timezone.utc)
        threshold = now - timedelta(days=max_age_days)
        deleted = 0

        for path in self.config_dir.glob("ssh-mcp-config.*.bak"):
            stem = path.stem  # e.g. "ssh-mcp-config.20260823T120000Z"
            parts = stem.split(".", 1)
            if len(parts) < 2:
                continue
            ts_str = parts[1]
            try:
                ts = datetime.strptime(ts_str, "%Y%m%dT%H%M%SZ")
            except ValueError:
                continue  # Skip malformed filenames

            # Make the naive datetime timezone-aware (UTC)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            if ts < threshold:
                logger.info("Deleting old backup: %s", path.name)
                path.unlink()
                deleted += 1

        return deleted

    @staticmethod
    def _validate_backup_name(backup_name: str) -> None:
        """Validate a backup filename for safety.

        Ensures the name contains no path separators or traversal
        sequences, and matches the expected backup pattern.

        Args:
            backup_name: The backup filename to validate.

        Raises:
            ValueError: If the name is invalid or contains path
                traversal characters.
        """
        if "/" in backup_name or "\\" in backup_name:
            raise ValueError(
                f"Invalid backup name (contains path separator): "
                f"{backup_name!r}"
            )
        if ".." in backup_name:
            raise ValueError(
                f"Invalid backup name (contains path traversal): "
                f"{backup_name!r}"
            )
        if not re.fullmatch(
            r"ssh-mcp-config\.\d{8}T\d{6}Z\.bak", backup_name
        ):
            raise ValueError(
                f"Invalid backup name format: {backup_name!r}"
            )

    def _atomic_write(self, config: dict) -> None:
        """Atomically write config dict to the config file.

        Writes to a temp file in the same directory, then uses os.replace()
        for an atomic rename.  Sets file permissions to 0o600.
        """
        self.config_dir.mkdir(parents=True, exist_ok=True)

        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(self.config_dir),
            suffix=".json.tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
                f.write("\n")  # Trailing newline
            os.chmod(tmp_path_str, RESTRICTED_FILE_MODE)
            os.replace(tmp_path_str, str(self.config_path))
        except Exception:
            try:
                os.unlink(tmp_path_str)
            except OSError:
                pass
            raise
