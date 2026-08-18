"""SecretsManager: load and merge secrets from ``secrets.json`` and env vars.

Secrets (SSH target ``password`` values and API-key ``key_hash`` values) are
kept out of the main configuration file and merged into it at load time with
the following precedence:

    env vars (``MCP_SSH_SECRET_*``)  >  ``secrets.json``  >  main config file

The module performs no I/O, reads no environment variables, and spawns no
threads at import time — all work happens inside :class:`SecretsManager`
methods.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

from lib.constants import (
    DEFAULT_SECRETS_FILENAME,
    LOG_FORMAT_VERSION,
    MCP_SSH_SECRET_PREFIX,
    RESTRICTED_FILE_MODE,
    SECRETS_FILE_MODE,
)
from lib.exceptions import SecretsError


def _normalize_identifier(value: str) -> str:
    """Upper-case *value* and replace hyphens with underscores.

    Env-var identifiers use this form (e.g. ``ci-bot`` → ``CI_BOT``), so it
    is used to match env-var suffixes back to config ids/names.
    """
    return value.upper().replace("-", "_")


class SecretsManager:
    """Loads and merges secrets from a secrets file and environment variables.

    Secrets are merged **into a copy** of the caller's config; the input dict
    is never mutated.  Secret values are never logged — only counts and
    identifiers.

    Args:
        secrets_dir: Directory containing ``secrets.json``.
        logger: Optional :class:`~lib.loggers.BaseLogger` instance for
            structured secrets events.  When ``None``, events are skipped.
    """

    def __init__(self, secrets_dir: str | Path, logger=None) -> None:
        self._secrets_dir = Path(secrets_dir)
        self._logger = logger

    @property
    def secrets_path(self) -> Path:
        """Path to the ``secrets.json`` file managed by this instance."""
        return self._secrets_dir / DEFAULT_SECRETS_FILENAME

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> dict:
        """Load ``secrets.json`` if it exists.

        Returns:
            Parsed secrets dict.  Returns ``{}`` when the file does not exist
            (a missing secrets file is valid).

        Raises:
            SecretsError: If the file exists but cannot be parsed or is not a
                JSON object.
        """
        path = self.secrets_path
        if not path.exists():
            return {}

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise SecretsError(
                f"Failed to read secrets file '{path}': {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise SecretsError(
                f"Secrets file '{path}' must contain a JSON object"
            )

        self._check_permissions(path)
        self._emit(
            "secrets.load",
            "Secrets file loaded",
            success=True,
            ssh_target_count=len(data.get("ssh_targets", {})) if isinstance(data.get("ssh_targets"), dict) else 0,
            api_key_count=len(data.get("api_keys", [])) if isinstance(data.get("api_keys"), list) else 0,
        )
        return data

    def _check_permissions(self, path: Path, *, fix: bool = False) -> bool:
        """Warn (and optionally correct) when a file is too permissive.

        When *fix* is ``True`` and group/world read or write bits are set, the
        file is chmod'd to :data:`RESTRICTED_FILE_MODE` and a
        ``secrets.permissions_fixed`` event is emitted.

        Returns True when a mode change was applied, otherwise False.
        """
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            return False

        if mode & 0o077:
            if fix:
                os.chmod(path, RESTRICTED_FILE_MODE)
                self._emit(
                    "secrets.permissions_fixed",
                    f"Secrets file '{path}' permissions corrected to "
                    f"{RESTRICTED_FILE_MODE:o}",
                    success=True,
                    mode=oct(mode),
                    fixed_mode=oct(RESTRICTED_FILE_MODE),
                    log_level="WARNING",
                )
                return True
            self._emit(
                "secrets.permissions_insecure",
                f"Secrets file '{path}' permissions are too permissive "
                f"(mode {mode:o}); expected {SECRETS_FILE_MODE:o}",
                success=False,
                mode=oct(mode),
                expected_mode=oct(SECRETS_FILE_MODE),
                log_level="WARNING",
            )
        return False

    def fix_permissions(self) -> bool:
        """Chmod ``secrets.json`` to ``RESTRICTED_FILE_MODE`` if it exists.

        Returns True if a change was applied, False if the file is absent or
        already secure.
        """
        path = self.secrets_path
        if not path.exists():
            return False
        return self._check_permissions(path, fix=True)

    # ------------------------------------------------------------------
    # Merging
    # ------------------------------------------------------------------

    def merge(self, base_config: dict) -> dict:
        """Return a copy of *base_config* with secrets merged in.

        Precedence: env vars > ``secrets.json`` > *base_config*.  The input
        dict is left unchanged.

        Args:
            base_config: The validated-or-raw main config dict.

        Returns:
            A new dict with SSH target passwords and API-key hashes patched in.
        """
        merged = copy.deepcopy(base_config) if isinstance(base_config, dict) else {}

        file_secrets = self.load()
        self._apply_file_secrets(merged, file_secrets)

        passwords, api_keys, unknown = self._read_env_secrets()
        self._apply_env_passwords(merged, passwords)
        env_api_entries = [
            {"name": name, "key_hash": value}
            for name, value in api_keys.items()
            if value  # empty env-var values are treated as unset
        ]
        unmatched_api = self._patch_api_key_hashes(merged, env_api_entries)
        for identifier in unknown:
            self._emit_unknown_env_var(identifier)
        for name in unmatched_api:
            self._emit_unknown_env_var(name)

        return merged

    # ------------------------------------------------------------------
    # File secrets application
    # ------------------------------------------------------------------

    def _apply_file_secrets(self, config: dict, file_secrets: dict) -> None:
        """Patch *config* in-place with values from ``secrets.json``."""
        ssh_secrets = file_secrets.get("ssh_targets")
        targets = config.get("ssh_targets")
        if isinstance(ssh_secrets, dict) and isinstance(targets, dict):
            for tid, secret_def in ssh_secrets.items():
                if not isinstance(secret_def, dict):
                    continue
                password = secret_def.get("password")
                if password is None:
                    continue
                target = targets.get(tid)
                if isinstance(target, dict):
                    target["password"] = password

        api_secrets = file_secrets.get("api_keys")
        if isinstance(api_secrets, list):
            self._patch_api_key_hashes(config, api_secrets)

    # ------------------------------------------------------------------
    # Env-var secrets application
    # ------------------------------------------------------------------

    def _read_env_secrets(self) -> tuple[dict[str, str], dict[str, str], list[str]]:
        """Scan ``os.environ`` for ``MCP_SSH_SECRET_*`` variables.

        Returns:
            A tuple of ``(passwords, api_keys, unknown)`` where ``passwords``
            and ``api_keys`` are keyed by normalized identifier (upper-cased,
            ``-`` → ``_``) and ``unknown`` lists unrecognized suffixes.
        """
        passwords: dict[str, str] = {}
        api_keys: dict[str, str] = {}
        unknown: list[str] = []

        for var, value in os.environ.items():
            if not var.startswith(MCP_SSH_SECRET_PREFIX):
                continue
            suffix = var[len(MCP_SSH_SECRET_PREFIX):]
            if suffix.startswith("PASSWORD_"):
                identifier = suffix[len("PASSWORD_"):]
                if identifier:
                    passwords[identifier] = value
                else:
                    unknown.append(var)
            elif suffix.startswith("API_KEY_"):
                name = suffix[len("API_KEY_"):]
                if name:
                    api_keys[name] = value
                else:
                    unknown.append(var)
            else:
                unknown.append(var)

        return passwords, api_keys, unknown

    def _apply_env_passwords(self, config: dict, passwords: dict[str, str]) -> None:
        """Patch SSH target passwords from env vars.

        An empty env-var value is treated as "unset" and falls through to the
        next source.  Identifiers are matched case-insensitively against the
        config's target ids (``-`` and ``_`` are interchangeable).
        """
        targets = config.get("ssh_targets")
        if not isinstance(targets, dict):
            return

        id_by_normalized = {
            _normalize_identifier(str(tid)): tid for tid in targets
        }

        for identifier, value in passwords.items():
            if not value:
                continue
            tid = id_by_normalized.get(_normalize_identifier(identifier))
            if tid is None:
                self._emit_unknown_env_var(identifier)
                continue
            target = targets.get(tid)
            if isinstance(target, dict):
                target["password"] = value

    def _patch_api_key_hashes(
        self, config: dict, entries: list[dict]
    ) -> list[str]:
        """Patch ``api_keys`` ``key_hash`` by name; never inject new entries.

        Only entries whose ``name`` already exists in
        ``allowed_commands.api_keys`` are patched.  Returns the list of names
        that did not match an existing entry.
        """
        allowed = config.get("allowed_commands")
        if not isinstance(allowed, dict):
            return []
        api_keys = allowed.get("api_keys")
        if not isinstance(api_keys, list):
            return []

        unmatched: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            key_hash = entry.get("key_hash")
            if not isinstance(name, str) or key_hash is None:
                continue
            normalized = _normalize_identifier(name)
            found = False
            for target_entry in api_keys:
                if not isinstance(target_entry, dict):
                    continue
                existing_name = target_entry.get("name")
                if (
                    isinstance(existing_name, str)
                    and _normalize_identifier(existing_name) == normalized
                ):
                    target_entry["key_hash"] = key_hash
                    found = True
                    break
            if not found:
                unmatched.append(name)
        return unmatched

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _emit(self, event: str, message: str, **extra) -> None:
        """Emit a structured secrets event if a logger is configured.

        Never includes secret values — only counts, identifiers, and modes.
        """
        if self._logger is None:
            return

        import datetime

        from lib.request_context import get_request_id

        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event,
            "success": extra.pop("success", True),
            "message": message,
            "secrets_path": str(self.secrets_path),
            "request_id": get_request_id(),
            "log_level": extra.pop("log_level", "INFO"),
            "log_format_version": LOG_FORMAT_VERSION,
        }
        entry.update(extra)
        self._logger.log(entry)

    def _emit_unknown_env_var(self, identifier: str) -> None:
        """Emit a warning for an unrecognized or unreferenced env secret."""
        self._emit(
            "secrets.unknown_env_var",
            f"Environment secret for '{identifier}' does not match any "
            "configured SSH target or API key and was ignored",
            success=False,
            identifier=identifier,
            log_level="WARNING",
        )
