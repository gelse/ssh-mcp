"""Tests for lib.secrets — SecretsManager loading, merging, and permissions."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from lib.exceptions import SecretsError
from lib.secrets import SecretsManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_HASH = "sha256:" + ("a" * 64)
VALID_HASH_2 = "sha256:" + ("b" * 64)


def _write_secrets(tmpdir: str, secrets_dict: dict) -> str:
    """Write *secrets_dict* as ``secrets.json`` inside *tmpdir*."""
    secrets_path = Path(tmpdir) / "secrets.json"
    secrets_path.write_text(json.dumps(secrets_dict), encoding="utf-8")
    return str(secrets_path)


def _base_config() -> dict:
    """Return a main-config dict with one target and one API key."""
    return {
        "version": 1,
        "ssh_targets": {
            "testbox": {
                "host": "10.0.0.1",
                "username": "admin",
                "password": "configpass",
            },
        },
        "allowed_commands": {
            "default": [{"targets": ["*"], "commands": ["hostname"]}],
            "api_keys": [
                {
                    "name": "ci-bot",
                    "key_hash": VALID_HASH,
                    "rules": [{"targets": ["*"], "commands": ["hostname"]}],
                },
            ],
            "networks": [],
        },
    }


class RecordingLogger:
    """Duck-typed :class:`~lib.loggers.BaseLogger` that records entries."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, entry: dict) -> None:
        self.entries.append(entry)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Tests: loading
# ---------------------------------------------------------------------------


class TestLoad:
    def test_load_existing_secrets_file(self):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"version": 1, "ssh_targets": {"testbox": {"password": "s3cret"}}})
            mgr = SecretsManager(td)
            data = mgr.load()
            assert data["ssh_targets"]["testbox"]["password"] == "s3cret"
            assert mgr.secrets_path == Path(td) / "secrets.json"

    def test_load_missing_secrets_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = SecretsManager(td)
            assert mgr.load() == {}

    def test_load_invalid_json_raises(self):
        with tempfile.TemporaryDirectory() as td:
            secrets_path = Path(td) / "secrets.json"
            secrets_path.write_text("{not valid json", encoding="utf-8")
            mgr = SecretsManager(td)
            with pytest.raises(SecretsError):
                mgr.load()

    def test_load_non_object_raises(self):
        with tempfile.TemporaryDirectory() as td:
            secrets_path = Path(td) / "secrets.json"
            secrets_path.write_text(json.dumps(["a", "list"]), encoding="utf-8")
            mgr = SecretsManager(td)
            with pytest.raises(SecretsError):
                mgr.load()


# ---------------------------------------------------------------------------
# Tests: merging
# ---------------------------------------------------------------------------


class TestMerge:
    def test_merge_precedence_env_over_file_over_config(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"ssh_targets": {"testbox": {"password": "filepass"}}})
            monkeypatch.setenv("MCP_SSH_SECRET_PASSWORD_TESTBOX", "envpass")
            mgr = SecretsManager(td)
            base = _base_config()
            merged = mgr.merge(base)
            assert merged["ssh_targets"]["testbox"]["password"] == "envpass"
            # input unchanged
            assert base["ssh_targets"]["testbox"]["password"] == "configpass"

    def test_merge_file_over_config(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"ssh_targets": {"testbox": {"password": "filepass"}}})
            monkeypatch.delenv("MCP_SSH_SECRET_PASSWORD_TESTBOX", raising=False)
            mgr = SecretsManager(td)
            merged = mgr.merge(_base_config())
            assert merged["ssh_targets"]["testbox"]["password"] == "filepass"

    def test_merge_config_fallback_when_no_secrets(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            monkeypatch.delenv("MCP_SSH_SECRET_PASSWORD_TESTBOX", raising=False)
            mgr = SecretsManager(td)
            merged = mgr.merge(_base_config())
            assert merged["ssh_targets"]["testbox"]["password"] == "configpass"

    def test_api_key_merge_by_name(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(
                td,
                {
                    "api_keys": [
                        {"name": "ci-bot", "key_hash": VALID_HASH_2},
                        {"name": "unknown-key", "key_hash": VALID_HASH_2},
                    ],
                },
            )
            monkeypatch.delenv("MCP_SSH_SECRET_API_KEY_CI_BOT", raising=False)
            mgr = SecretsManager(td)
            merged = mgr.merge(_base_config())
            api_keys = merged["allowed_commands"]["api_keys"]
            # Only the matching name is patched; unknown is not injected.
            assert len(api_keys) == 1
            assert api_keys[0]["name"] == "ci-bot"
            assert api_keys[0]["key_hash"] == VALID_HASH_2

    def test_merge_returns_new_dict_and_does_not_mutate(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"ssh_targets": {"testbox": {"password": "filepass"}}})
            monkeypatch.delenv("MCP_SSH_SECRET_PASSWORD_TESTBOX", raising=False)
            mgr = SecretsManager(td)
            base = _base_config()
            merged = mgr.merge(base)
            assert merged is not base
            assert base["ssh_targets"]["testbox"]["password"] == "configpass"

    def test_empty_env_var_treated_as_unset(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"ssh_targets": {"testbox": {"password": "filepass"}}})
            monkeypatch.setenv("MCP_SSH_SECRET_PASSWORD_TESTBOX", "")
            mgr = SecretsManager(td)
            merged = mgr.merge(_base_config())
            # Empty env var falls through to the secrets file.
            assert merged["ssh_targets"]["testbox"]["password"] == "filepass"



# ---------------------------------------------------------------------------
# Tests: permissions
# ---------------------------------------------------------------------------


class TestPermissions:
    def test_world_readable_triggers_warning(self):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"version": 1})
            os.chmod(Path(td) / "secrets.json", 0o644)
            logger = RecordingLogger()
            mgr = SecretsManager(td, logger=logger)
            mgr.load()
            events = [e for e in logger.entries if e["event"] == "secrets.permissions_insecure"]
            assert len(events) == 1
            assert events[0]["success"] is False

    def test_0600_does_not_warn(self):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"version": 1})
            os.chmod(Path(td) / "secrets.json", 0o600)
            logger = RecordingLogger()
            mgr = SecretsManager(td, logger=logger)
            mgr.load()
            events = [e for e in logger.entries if e["event"] == "secrets.permissions_insecure"]
            assert events == []

    def test_fix_permissions_corrects_insecure_mode(self):
        """``fix_permissions()`` chmods an insecure secrets file to 0o600."""
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"version": 1})
            sec_path = Path(td) / "secrets.json"
            os.chmod(sec_path, 0o644)
            logger = RecordingLogger()
            mgr = SecretsManager(td, logger=logger)

            changed = mgr.fix_permissions()

            assert changed is True
            assert os.stat(sec_path).st_mode & 0o777 == 0o600
            events = [e for e in logger.entries if e["event"] == "secrets.permissions_fixed"]
            assert len(events) == 1
            assert events[0]["success"] is True

    def test_fix_permissions_missing_file_returns_false(self):
        """``fix_permissions()`` returns False for a missing secrets file."""
        with tempfile.TemporaryDirectory() as td:
            mgr = SecretsManager(td)
            assert mgr.fix_permissions() is False

    def test_fix_permissions_already_secure_no_change(self):
        """``fix_permissions()`` returns False when the file is already 0o600."""
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"version": 1})
            os.chmod(Path(td) / "secrets.json", 0o600)
            mgr = SecretsManager(td)
            assert mgr.fix_permissions() is False


# ---------------------------------------------------------------------------
# Tests: secret non-leak
# ---------------------------------------------------------------------------


class TestNonLeak:
    def test_merge_never_logs_secret_values(self, monkeypatch):
        with tempfile.TemporaryDirectory() as td:
            _write_secrets(td, {"ssh_targets": {"testbox": {"password": "supersecret"}}})
            monkeypatch.setenv("MCP_SSH_SECRET_PASSWORD_TESTBOX", "envsecret")
            logger = RecordingLogger()
            mgr = SecretsManager(td, logger=logger)
            mgr.merge(_base_config())
            for entry in logger.entries:
                serialized = json.dumps(entry)
                assert "supersecret" not in serialized
                assert "envsecret" not in serialized
                assert "configpass" not in serialized


# ---------------------------------------------------------------------------
# Tests: env-var name mapping
# ---------------------------------------------------------------------------


class TestEnvVarMapping:
    @pytest.mark.parametrize(
        ("env_name", "expected_password"),
        [
            ("MCP_SSH_SECRET_PASSWORD_TESTBOX", "pw1"),
            ("MCP_SSH_SECRET_PASSWORD_testbox", "pw2"),
        ],
    )
    def test_env_password_matching(self, monkeypatch, env_name, expected_password):
        with tempfile.TemporaryDirectory() as td:
            monkeypatch.setenv(env_name, expected_password)
            mgr = SecretsManager(td)
            merged = mgr.merge(_base_config())
            assert merged["ssh_targets"]["testbox"]["password"] == expected_password

    def test_env_password_hyphen_target_id(self, monkeypatch):
        """A hyphenated target id matches its underscore-normalized env var."""
        config = _base_config()
        config["ssh_targets"] = {
            "ci-bot": {
                "host": "10.0.0.2",
                "username": "bot",
                "password": "configpass",
            },
        }
        monkeypatch.setenv("MCP_SSH_SECRET_PASSWORD_ci-bot", "hyphenpw")
        with tempfile.TemporaryDirectory() as td:
            mgr = SecretsManager(td)
            merged = mgr.merge(config)
            assert merged["ssh_targets"]["ci-bot"]["password"] == "hyphenpw"

    @pytest.mark.parametrize(
        ("env_name", "expected_hash"),
        [
            ("MCP_SSH_SECRET_API_KEY_CI_BOT", VALID_HASH_2),
            ("MCP_SSH_SECRET_API_KEY_ci-bot", VALID_HASH_2),
        ],
    )
    def test_env_api_key_matching(self, monkeypatch, env_name, expected_hash):
        with tempfile.TemporaryDirectory() as td:
            monkeypatch.setenv(env_name, expected_hash)
            mgr = SecretsManager(td)
            merged = mgr.merge(_base_config())
            assert merged["allowed_commands"]["api_keys"][0]["key_hash"] == expected_hash
