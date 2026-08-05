"""ConfigManager: loading, validation, and default creation for SSH MCP config.

Provides a thread-safe ConfigManager that loads a JSON config file,
validates it against a strict schema, applies defaults, and exposes
query methods for SSH targets.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Raised when config validation fails. Contains a human-readable message."""

    def __init__(self, message: str, field: str | None = None):
        self.message = message
        self.field = field
        super().__init__(message)


class ConfigManager:
    """Loads, validates, and provides access to the SSH MCP configuration.

    The config file is expected at ``<config_dir>/ssh-mcp-config.json``.
    If the file does not exist on first load, a default is copied from
    the project root's ``default-config.json``.

    All public reads return shallow copies so callers cannot mutate
    internal state.
    """

    def __init__(self, config_dir: str):
        self._config_dir = Path(config_dir)
        self._config_path = self._config_dir / "ssh-mcp-config.json"
        self._lock = threading.Lock()
        self._data: dict = {}
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop_event = threading.Event()
        self._last_mtime: float = 0.0
        self.load()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def config_path(self) -> Path:
        """Path to the active configuration file."""
        return self._config_path

    @property
    def data(self) -> dict:
        """Shallow copy of the validated, normalized configuration."""
        with self._lock:
            return self._data.copy()

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def load(self) -> dict:
        """Load config from disk, validate, and store internally.

        Returns the validated dict.
        """
        if not self._config_path.exists():
            self._ensure_default_config()
            if not self._config_path.exists():
                raise RuntimeError(
                    "Default config creation failed — "
                    f"'{self._config_path}' still does not exist"
                )

        raw = self._read_json()
        validated = self._validate(raw)

        with self._lock:
            self._data = validated
            self._last_mtime = os.path.getmtime(self._config_path)

        logger.info("Config loaded from %s", self._config_path)
        return validated

    def reload(self) -> bool:
        """Re-read the config file and atomically replace in-memory data.

        Returns ``True`` if the reload succeeded, ``False`` if validation
        failed (the existing data is preserved).
        """
        try:
            raw = self._read_json()
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read config for reload: %s", exc)
            return False

        try:
            validated = self._validate(raw)
        except ConfigValidationError as exc:
            logger.error("Reload validation failed — keeping existing config: %s", exc)
            return False

        with self._lock:
            self._data = validated
            self._last_mtime = os.path.getmtime(self._config_path)

        logger.info("Config reloaded from %s", self._config_path)
        return True

    def get_ssh_target(self, target_id: str) -> dict | None:
        """Return the SSH target dict for *target_id*, or ``None``."""
        return self.data.get("ssh_targets", {}).get(target_id)

    def list_ssh_targets(self) -> list[str]:
        """Return the list of configured SSH target IDs."""
        return list(self.data.get("ssh_targets", {}).keys())

    # ------------------------------------------------------------------
    # Watcher (hot-reload)
    # ------------------------------------------------------------------

    @property
    def watcher_running(self) -> bool:
        """Return True if the watcher thread is currently active."""
        return self._watcher_thread is not None and self._watcher_thread.is_alive()

    def start_watcher(self, polling_interval: float = 15.0) -> None:
        """Start the background polling thread for hot-reload.

        Spawns a daemon thread that checks ``os.path.getmtime()``
        of the config file every *polling_interval* seconds.
        If modification time changed since last load, calls
        :meth:`reload`.

        Idempotent: calling multiple times has no effect if already
        running.
        """
        if self._watcher_thread is not None and self._watcher_thread.is_alive():
            return

        self._watcher_stop_event.clear()
        self._last_mtime = os.path.getmtime(self._config_path)

        self._watcher_thread = threading.Thread(
            target=self._watcher_loop,
            args=(polling_interval,),
            name="config-watcher",
            daemon=True,
        )
        self._watcher_thread.start()
        logger.info(
            "Config watcher started (interval=%.1fs, path=%s)",
            polling_interval,
            self._config_path,
        )

    def stop_watcher(self) -> None:
        """Stop the background polling thread gracefully.

        Signals the thread to exit via a ``threading.Event`` and joins
        with a timeout.  Safe to call if the watcher was never started.
        """
        self._watcher_stop_event.set()

        if self._watcher_thread is not None and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=20.0)
            if self._watcher_thread.is_alive():
                logger.warning("Config watcher thread did not exit within timeout")
            self._watcher_thread = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _watcher_loop(self, polling_interval: float) -> None:
        """Poll ``os.path.getmtime()`` and trigger :meth:`reload` on change."""
        while not self._watcher_stop_event.is_set():
            self._watcher_stop_event.wait(timeout=polling_interval)

            if self._watcher_stop_event.is_set():
                break

            try:
                if not self._config_path.exists():
                    logger.warning(
                        "Config file %s no longer exists — skipping reload",
                        self._config_path,
                    )
                    continue

                current_mtime = os.path.getmtime(self._config_path)
                if current_mtime != self._last_mtime:
                    logger.info("Config file changed, reloading...")
                    success = self.reload()
                    if success:
                        logger.info("Config reloaded successfully")
                    else:
                        logger.error(
                            "Config reload failed, keeping previous config"
                        )
            except Exception:
                logger.exception("Unhandled error in config watcher loop")

    def _ensure_default_config(self) -> None:
        """Copy the bundled default config to ``self._config_path``."""
        source = Path(__file__).parent.parent / "default-config.json"
        if not source.exists():
            raise FileNotFoundError(
                f"Default config template not found at '{source}'"
            )

        self._config_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, self._config_path)
        os.chmod(self._config_path, 0o600)
        logger.info("Created default config at %s", self._config_path)

    def _read_json(self) -> dict:
        """Read and parse the JSON config file."""
        with open(self._config_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, config: dict) -> dict:
        """Validate *config* and return a deep copy with defaults applied.

        Raises :class:`ConfigValidationError` on the first violation.
        """
        if not isinstance(config, dict):
            raise ConfigValidationError("Config root must be a JSON object")

        # ---- known top-level keys ----
        KNOWN_TOP_KEYS = {
            "version",
            "ssh_targets",
            "block_patterns",
            "allowed_commands",
            "settings",
        }
        for key in config:
            if key not in KNOWN_TOP_KEYS:
                raise ConfigValidationError(
                    f"Unknown top-level key '{key}'",
                    field=key,
                )

        # -- version --
        version = config.get("version")
        if not isinstance(version, int) or version < 1:
            raise ConfigValidationError(
                f"'version' must be a positive integer, got {version!r}",
                field="version",
            )
        if version != 1:
            raise ConfigValidationError(
                f"Unsupported config version {version!r} (only version 1 is supported)",
                field="version",
            )

        # -- ssh_targets --
        ssh_targets_raw = config.get("ssh_targets")
        if not isinstance(ssh_targets_raw, dict) or len(ssh_targets_raw) == 0:
            raise ConfigValidationError(
                "'ssh_targets' must be a non-empty object",
                field="ssh_targets",
            )

        ssh_targets = {}
        ALLOWED_TARGET_KEYS = {"host", "port", "username", "private_key", "password"}
        for tid, tdef in ssh_targets_raw.items():
            if not isinstance(tdef, dict):
                raise ConfigValidationError(
                    f"ssh_target '{tid}' must be an object",
                    field=f"ssh_targets.{tid}",
                )
            for k in tdef:
                if k not in ALLOWED_TARGET_KEYS:
                    raise ConfigValidationError(
                        f"Unknown key '{k}' in ssh_target '{tid}'",
                        field=f"ssh_targets.{tid}.{k}",
                    )

            host = tdef.get("host")
            if not isinstance(host, str) or not host.strip():
                raise ConfigValidationError(
                    f"ssh_targets '{tid}': 'host' must be a non-empty string",
                    field=f"ssh_targets.{tid}.host",
                )

            username = tdef.get("username")
            if not isinstance(username, str) or not username.strip():
                raise ConfigValidationError(
                    f"ssh_targets '{tid}': 'username' must be a non-empty string",
                    field=f"ssh_targets.{tid}.username",
                )

            port = tdef.get("port", 22)
            if port is not None and (not isinstance(port, int) or port < 1 or port > 65535):
                raise ConfigValidationError(
                    f"ssh_targets '{tid}': 'port' must be an integer 1-65535, got {port!r}",
                    field=f"ssh_targets.{tid}.port",
                )

            private_key = tdef.get("private_key", "")
            password = tdef.get("password", "")
            has_key = isinstance(private_key, str) and private_key.strip() != ""
            has_pw = isinstance(password, str) and password.strip() != ""
            if not has_key and not has_pw:
                raise ConfigValidationError(
                    f"ssh_targets '{tid}': at least one of 'private_key' or 'password' must be non-empty",
                    field=f"ssh_targets.{tid}",
                )
            if "private_key" in tdef and (not isinstance(private_key, str) or private_key.strip() == ""):
                raise ConfigValidationError(
                    f"ssh_targets '{tid}': 'private_key' must be a non-empty string",
                    field=f"ssh_targets.{tid}.private_key",
                )
            if "password" in tdef and (not isinstance(password, str) or password.strip() == ""):
                raise ConfigValidationError(
                    f"ssh_targets '{tid}': 'password' must be a non-empty string",
                    field=f"ssh_targets.{tid}.password",
                )

            normalized = {
                "host": host,
                "port": port,
                "username": username,
            }
            if has_key:
                normalized["private_key"] = private_key
            if has_pw:
                normalized["password"] = password
            ssh_targets[tid] = normalized

        # Collect ssh target IDs for cross-reference validation
        ssh_target_ids = set(ssh_targets.keys())

        # -- block_patterns --
        block_patterns_raw = config.get("block_patterns", [])
        if not isinstance(block_patterns_raw, list):
            raise ConfigValidationError(
                "'block_patterns' must be a list of strings",
                field="block_patterns",
            )
        for idx, pat in enumerate(block_patterns_raw):
            if not isinstance(pat, str):
                raise ConfigValidationError(
                    f"'block_patterns[{idx}]' must be a string, got {type(pat).__name__}",
                    field=f"block_patterns[{idx}]",
                )
            try:
                re.compile(pat)
            except re.error as exc:
                raise ConfigValidationError(
                    f"'block_patterns[{idx}]' is not a valid regex: {exc}",
                    field=f"block_patterns[{idx}]",
                )

        # -- allowed_commands --
        allowed_raw = config.get("allowed_commands")
        if not isinstance(allowed_raw, dict):
            raise ConfigValidationError(
                "'allowed_commands' must be an object",
                field="allowed_commands",
            )

        allowed = {}

        # --- default rules ---
        default_rules_raw = allowed_raw.get("default")
        if not isinstance(default_rules_raw, list) or len(default_rules_raw) == 0:
            raise ConfigValidationError(
                "'allowed_commands.default' must be a non-empty list of rules",
                field="allowed_commands.default",
            )
        allowed["default"] = self._validate_rules(
            default_rules_raw, ssh_target_ids, "allowed_commands.default"
        )

        # --- api_keys ---
        api_keys_raw = allowed_raw.get("api_keys")
        if not isinstance(api_keys_raw, list):
            raise ConfigValidationError(
                "'allowed_commands.api_keys' must be a list",
                field="allowed_commands.api_keys",
            )
        api_keys = []
        KEY_HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
        for idx, entry in enumerate(api_keys_raw):
            if not isinstance(entry, dict):
                raise ConfigValidationError(
                    f"'api_keys[{idx}]' must be an object",
                    field=f"api_keys[{idx}]",
                )
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ConfigValidationError(
                    f"'api_keys[{idx}].name' must be a non-empty string",
                    field=f"api_keys[{idx}].name",
                )
            key_hash = entry.get("key_hash")
            if not isinstance(key_hash, str) or not KEY_HASH_RE.match(key_hash):
                raise ConfigValidationError(
                    f"'api_keys[{idx}].key_hash' must match pattern 'sha256:<64 hex chars>'",
                    field=f"api_keys[{idx}].key_hash",
                )
            rules_raw = entry.get("rules")
            if not isinstance(rules_raw, list) or len(rules_raw) == 0:
                raise ConfigValidationError(
                    f"'api_keys[{idx}].rules' must be a non-empty list of rules",
                    field=f"api_keys[{idx}].rules",
                )
            rules = self._validate_rules(
                rules_raw, ssh_target_ids, f"api_keys[{idx}].rules"
            )
            api_keys.append({"name": name, "key_hash": key_hash, "rules": rules})
        allowed["api_keys"] = api_keys

        # --- networks ---
        networks_raw = allowed_raw.get("networks")
        if not isinstance(networks_raw, list):
            raise ConfigValidationError(
                "'allowed_commands.networks' must be a list",
                field="allowed_commands.networks",
            )
        networks = []
        for idx, entry in enumerate(networks_raw):
            if not isinstance(entry, dict):
                raise ConfigValidationError(
                    f"'networks[{idx}]' must be an object",
                    field=f"networks[{idx}]",
                )
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ConfigValidationError(
                    f"'networks[{idx}].name' must be a non-empty string",
                    field=f"networks[{idx}].name",
                )
            cidr = entry.get("range")
            if not isinstance(cidr, str):
                raise ConfigValidationError(
                    f"'networks[{idx}].range' must be a string",
                    field=f"networks[{idx}].range",
                )
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigValidationError(
                    f"'networks[{idx}].range' is not a valid CIDR: {exc}",
                    field=f"networks[{idx}].range",
                )
            rules_raw = entry.get("rules")
            if not isinstance(rules_raw, list) or len(rules_raw) == 0:
                raise ConfigValidationError(
                    f"'networks[{idx}].rules' must be a non-empty list of rules",
                    field=f"networks[{idx}].rules",
                )
            rules = self._validate_rules(
                rules_raw, ssh_target_ids, f"networks[{idx}].rules"
            )
            networks.append({"name": name, "range": cidr, "rules": rules})
        allowed["networks"] = networks

        # -- settings --
        settings_raw = config.get("settings")
        if not isinstance(settings_raw, dict):
            raise ConfigValidationError(
                "'settings' must be an object",
                field="settings",
            )
        ALLOWED_SETTINGS = {"max_output_length", "command_timeout_max"}
        for sk in settings_raw:
            if sk not in ALLOWED_SETTINGS:
                raise ConfigValidationError(
                    f"Unknown key '{sk}' in 'settings'",
                    field=f"settings.{sk}",
                )
        max_output = settings_raw.get("max_output_length")
        if not isinstance(max_output, int) or max_output < 1:
            raise ConfigValidationError(
                f"'settings.max_output_length' must be an integer >= 1, got {max_output!r}",
                field="settings.max_output_length",
            )
        timeout_max = settings_raw.get("command_timeout_max")
        if not isinstance(timeout_max, int) or timeout_max < 1:
            raise ConfigValidationError(
                f"'settings.command_timeout_max' must be an integer >= 1, got {timeout_max!r}",
                field="settings.command_timeout_max",
            )

        return {
            "version": version,
            "ssh_targets": ssh_targets,
            "block_patterns": list(block_patterns_raw),
            "allowed_commands": allowed,
            "settings": {
                "max_output_length": max_output,
                "command_timeout_max": timeout_max,
            },
        }

    @staticmethod
    def _validate_rules(
        rules_raw: list,
        ssh_target_ids: set[str],
        field_prefix: str,
    ) -> list[dict]:
        """Validate a list of command-allowance rules.

        Each rule must have a non-empty ``targets`` list and a non-empty
        ``commands`` list.  Non-wildcard targets must exist in
        *ssh_target_ids*.
        """
        rules = []
        for idx, rule in enumerate(rules_raw):
            if not isinstance(rule, dict):
                raise ConfigValidationError(
                    f"'{field_prefix}[{idx}]' must be an object",
                    field=f"{field_prefix}[{idx}]",
                )
            targets = rule.get("targets")
            if not isinstance(targets, list) or len(targets) == 0:
                raise ConfigValidationError(
                    f"'{field_prefix}[{idx}].targets' must be a non-empty list",
                    field=f"{field_prefix}[{idx}].targets",
                )
            for t in targets:
                if not isinstance(t, str):
                    raise ConfigValidationError(
                        f"'{field_prefix}[{idx}].targets' entries must be strings",
                        field=f"{field_prefix}[{idx}].targets",
                    )
                if t != "*" and t not in ssh_target_ids:
                    raise ConfigValidationError(
                        f"'{field_prefix}[{idx}].targets' references unknown "
                        f"ssh_target '{t}'",
                        field=f"{field_prefix}[{idx}].targets",
                    )

            commands = rule.get("commands")
            if not isinstance(commands, list) or len(commands) == 0:
                raise ConfigValidationError(
                    f"'{field_prefix}[{idx}].commands' must be a non-empty list",
                    field=f"{field_prefix}[{idx}].commands",
                )
            for c in commands:
                if not isinstance(c, str):
                    raise ConfigValidationError(
                        f"'{field_prefix}[{idx}].commands' entries must be strings",
                        field=f"{field_prefix}[{idx}].commands",
                    )

            rules.append({"targets": list(targets), "commands": list(commands)})
        return rules
