"""Config schema version migration for the SSH MCP server.

Config files carry a top-level ``version`` integer.  When the schema
changes between releases, this module applies incremental, pure
transformations so an operator's existing config keeps working.  Every
migration is registered in :data:`MIGRATIONS`, keyed by the config
version it starts from; :func:`migrate_config` walks the chain in
ascending order up to (but excluding) :func:`latest_config_version`.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Callable

from lib.constants import (
    CONFIG_BACKUP_SUFFIX,
    LATEST_CONFIG_VERSION,
    MIGRATED_FILE_MODE,
)
from lib.exceptions import ConfigMigrationError


def _migrate_v1_to_v2(config: dict) -> dict:
    """Migrate a v1 config to v2.

    Placeholder migration: the schema is unchanged, so the input is
    copied as-is and only the ``version`` field is bumped to ``2``.  No
    input dict is ever mutated — a fresh copy is returned.

    Args:
        config: Validated v1 config dict.

    Returns:
        A new dict with ``version`` set to ``2``.
    """
    migrated = dict(config)
    migrated["version"] = 2
    return migrated


#: Registry mapping a starting config version to the migration that
#: advances it by one step.  Each migration is pure: it must return a new
#: dict and never mutate its input.
MIGRATIONS: dict[int, Callable[[dict], dict]] = {1: _migrate_v1_to_v2}


def get_config_version(config: dict) -> int:
    """Return the schema version of *config*.

    A missing ``version`` key is treated as version ``1`` (the original
    format predated version tracking).  A non-integer version or a
    version below ``1`` is rejected.

    Args:
        config: Raw config dict read from disk.

    Returns:
        The integer config schema version.

    Raises:
        ConfigMigrationError: If ``version`` is not an integer or is less
            than ``1``.
    """
    version = config.get("version")
    if version is None:
        return 1
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ConfigMigrationError(
            f"Invalid config version {version!r}; expected a positive integer"
        )
    return version


def latest_config_version() -> int:
    """Return the most recent config schema version this release supports."""
    return LATEST_CONFIG_VERSION


def migrate_config(config: dict) -> dict:
    """Apply all registered migrations to bring *config* up to the latest version.

    Migrations are applied in ascending version order, from the current
    version up to (but excluding) :func:`latest_config_version`.  When no
    migration is needed (the config is already current), the input dict
    is returned unchanged — literally the same object — so callers can
    detect whether a real change occurred.

    Args:
        config: Raw config dict, possibly at an older schema version.

    Returns:
        The input dict unchanged if already current, otherwise a new
        fully-migrated dict.

    Raises:
        ConfigMigrationError: If the config's version is newer than the
            latest version this release understands.
    """
    current = get_config_version(config)
    latest = latest_config_version()
    if current > latest:
        raise ConfigMigrationError(
            f"Config version {current} is newer than the latest supported "
            f"version {latest}"
        )
    if current == latest:
        return config

    migrated = config
    version = current
    while version < latest:
        migration = MIGRATIONS.get(version)
        if migration is None:
            raise ConfigMigrationError(
                f"No migration registered from config version {version} "
                f"to {version + 1}"
            )
        migrated = migration(migrated)
        next_version = get_config_version(migrated)
        if next_version <= version:
            raise ConfigMigrationError(
                f"Migration from version {version} did not advance the "
                f"config version (stayed at {next_version})"
            )
        version = next_version
    return migrated


def backup_config_file(config_path: Path) -> Path | None:
    """Write an atomic backup of *config_path* to ``<config_path>.bak``.

    The backup is created only if it does not already exist — an existing
    ``.bak`` is never overwritten.  The file is copied atomically (temp
    file in the same directory followed by :func:`os.replace`) and given
    :data:`MIGRATED_FILE_MODE` permissions.

    Args:
        config_path: Path to the source config file.

    Returns:
        The backup path on success, or ``None`` when no backup can be
        created (e.g. the source is missing or the filesystem is
        read-only).
    """
    backup_path = Path(str(config_path) + CONFIG_BACKUP_SUFFIX)
    if not config_path.exists() or backup_path.exists():
        return None
    try:
        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(config_path.parent), prefix=".backup_", suffix=".tmp"
        )
        os.close(fd)
        tmp_path = Path(tmp_path_str)
        try:
            with config_path.open("rb") as src, tmp_path.open("wb") as dst:
                while True:
                    chunk = src.read(1024 * 64)
                    if not chunk:
                        break
                    dst.write(chunk)
            os.chmod(tmp_path, MIGRATED_FILE_MODE)
            os.replace(tmp_path, backup_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
        return backup_path
    except (OSError, PermissionError):
        return None


def write_migrated_config(config_path: Path, migrated: dict) -> None:
    """Atomically write *migrated* as JSON to *config_path*.

    The file is written to a temporary file in the same directory and
    moved into place with :func:`os.replace`, then given
    :data:`MIGRATED_FILE_MODE` permissions.

    Args:
        config_path: Destination config file path.
        migrated: The migrated config dict to serialize.

    Raises:
        OSError: If the file cannot be written (e.g. read-only filesystem).
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(config_path.parent),
        prefix=".migrated_",
        suffix=".tmp",
        delete=False,
    ) as fh:
        tmp_path_str = fh.name
        json.dump(migrated, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(tmp_path_str, MIGRATED_FILE_MODE)
        os.replace(tmp_path_str, config_path)
    finally:
        if os.path.exists(tmp_path_str):
            os.unlink(tmp_path_str)
