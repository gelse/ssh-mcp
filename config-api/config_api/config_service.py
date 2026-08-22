"""Config file read/write/validate service.

Reads, validates, and atomically writes the SSH MCP configuration file,
reusing ``ConfigManager._validate()`` from ``lib/config.py``.
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from lib.config import ConfigManager
from lib.constants import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILENAME,
    RESTRICTED_FILE_MODE,
)
from lib.exceptions import ConfigValidationError


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

    def __init__(self, config_dir: str | None = None) -> None:
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

        # Step 2: Strip secrets from the validated config for writing
        clean = self._strip_secrets(validated)

        with self._write_lock:
            # Step 3: Backup
            self._create_backup()

            # Step 4-5: Atomic write
            self._atomic_write(clean)

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
