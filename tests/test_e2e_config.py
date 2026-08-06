"""End-to-end tests for the full config pipeline.

Exercises ConfigManager with the real default-config.json without
starting SSH connections or Docker containers.  Covers config loading,
validation, copy, hot-reload, thread safety, regex validation, and
snake_case field migration.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
import time
from pathlib import Path

import pytest

from lib.config import ConfigManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BUNDLED_DEFAULT = Path(__file__).parent.parent / "default-config.json"


def _load_bundled() -> dict:
    """Load the real default-config.json from the project root."""
    return json.loads(BUNDLED_DEFAULT.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Test 1: default config creation from empty directory
# ---------------------------------------------------------------------------


def test_default_config_creation_from_empty_dir():
    """ConfigManager copies bundled default-config.json into an empty dir."""
    with tempfile.TemporaryDirectory() as td:
        mgr = ConfigManager(td)
        data = mgr.data
        assert data["version"] == 1
        assert len(data["ssh_targets"]) == 12
        assert os.path.exists(mgr.config_path)

        # Verify content matches the bundled file
        bundled = _load_bundled()
        assert data["ssh_targets"].keys() == bundled["ssh_targets"].keys()
        assert data["settings"] == bundled["settings"]


# ---------------------------------------------------------------------------
# Test 2: full validation pass on bundled default-config.json
# ---------------------------------------------------------------------------


def test_full_validation_pass():
    """Load the bundled default-config.json and verify all its contents."""
    bundled = _load_bundled()

    # 2 placeholder targets
    assert len(bundled["ssh_targets"]) == 2
    expected_targets = {"example-server-1", "example-server-2"}
    assert set(bundled["ssh_targets"].keys()) == expected_targets

    # Every target has host, username, port, and private_key (or password)
    for tid, tdef in bundled["ssh_targets"].items():
        assert isinstance(tdef["host"], str) and tdef["host"], f"{tid}: host"
        assert isinstance(tdef["username"], str) and tdef["username"], f"{tid}: username"
        assert isinstance(tdef.get("port", 22), int), f"{tid}: port"
        assert tdef.get("private_key") or tdef.get("password"), f"{tid}: auth"

    # 10 block patterns
    assert len(bundled["block_patterns"]) == 10

    # Allowed commands: default has commands, api_keys empty, networks empty
    ac = bundled["allowed_commands"]
    assert len(ac["default"]) == 1
    assert sorted(ac["default"][0]["commands"])[0] == "cat"  # spot-check
    assert len(ac["default"][0]["commands"]) > 0
    assert ac["api_keys"] == []
    assert ac["networks"] == []

    # Settings
    assert bundled["settings"]["max_output_length"] == 50000
    assert bundled["settings"]["command_timeout_max"] == 120

    # Now load through ConfigManager to exercise validation
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / "ssh-mcp-config.json"
        dest.write_text(json.dumps(bundled), encoding="utf-8")
        mgr = ConfigManager(td)
        assert mgr.data["version"] == 1
        assert len(mgr.data["ssh_targets"]) == 12


# ---------------------------------------------------------------------------
# Test 3: config file permissions
# ---------------------------------------------------------------------------


def test_config_file_permissions():
    """Config file created by _ensure_default_config has 0o600 permissions."""
    with tempfile.TemporaryDirectory() as td:
        mgr = ConfigManager(td)
        st = os.stat(mgr.config_path)
        actual_mode = stat.S_IMODE(st.st_mode)
        assert actual_mode == 0o600, (
            f"Expected 0o600, got {oct(actual_mode)}"
        )


# ---------------------------------------------------------------------------
# Test 4: hot-reload detects new target
# ---------------------------------------------------------------------------


def test_hot_reload_new_target():
    """Watcher picks up a new SSH target added to the config file."""
    with tempfile.TemporaryDirectory() as td:
        cfg = _load_bundled()
        dest = Path(td) / "ssh-mcp-config.json"
        dest.write_text(json.dumps(cfg), encoding="utf-8")

        mgr = ConfigManager(td)
        mgr.start_watcher(polling_interval=0.2)

        assert "newbox" not in mgr.data["ssh_targets"]

        # Add a new target
        cfg["ssh_targets"]["newbox"] = {
            "host": "10.99.99.99",
            "username": "test",
            "private_key": "/tmp/key",
        }
        dest.write_text(json.dumps(cfg), encoding="utf-8")

        # Wait for watcher to pick up
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if "newbox" in mgr.data["ssh_targets"]:
                break
            time.sleep(0.05)
        else:
            mgr.stop_watcher()
            pytest.fail("Watcher did not detect new target within timeout")

        assert "newbox" in mgr.data["ssh_targets"]
        assert mgr.data["ssh_targets"]["newbox"]["host"] == "10.99.99.99"
        mgr.stop_watcher()


# ---------------------------------------------------------------------------
# Test 5: hot-reload rejects invalid JSON, preserves last good config
# ---------------------------------------------------------------------------


def test_hot_reload_invalid_json_preserves_old():
    """Writing invalid JSON does not corrupt in-memory config."""
    with tempfile.TemporaryDirectory() as td:
        cfg = _load_bundled()
        dest = Path(td) / "ssh-mcp-config.json"
        dest.write_text(json.dumps(cfg), encoding="utf-8")

        mgr = ConfigManager(td)
        mgr.start_watcher(polling_interval=0.2)

        original_targets = list(mgr.data["ssh_targets"].keys())

        # Write garbage
        dest.write_text("this is not valid json {{{", encoding="utf-8")

        time.sleep(0.6)  # give watcher time to attempt reload and reject

        # Data should still be the original valid config
        assert list(mgr.data["ssh_targets"].keys()) == original_targets
        mgr.stop_watcher()


# ---------------------------------------------------------------------------
# Test 6: block patterns are valid Python regex
# ---------------------------------------------------------------------------


def test_block_patterns_are_valid_regex():
    """All block patterns in the bundled default config compile as valid regex."""
    bundled = _load_bundled()
    for idx, pat in enumerate(bundled["block_patterns"]):
        try:
            re.compile(pat)
        except re.error as exc:
            pytest.fail(
                f"block_patterns[{idx}] = {pat!r} is not valid regex: {exc}"
            )

    # Also verify through ConfigManager validation
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / "ssh-mcp-config.json"
        dest.write_text(json.dumps(bundled), encoding="utf-8")
        mgr = ConfigManager(td)
        assert len(mgr.data["block_patterns"]) == 10


# ---------------------------------------------------------------------------
# Test 7: concurrent read/write safety
# ---------------------------------------------------------------------------


def test_concurrent_read_write_safety():
    """Multiple threads reading ssh_targets while config is reloaded don't
    cause corruption."""
    with tempfile.TemporaryDirectory() as td:
        cfg = _load_bundled()
        dest = Path(td) / "ssh-mcp-config.json"
        dest.write_text(json.dumps(cfg), encoding="utf-8")

        mgr = ConfigManager(td)
        mgr.start_watcher(polling_interval=0.1)
        errors = []

        def reader():
            try:
                for _ in range(200):
                    # Use .get("ssh_targets", {}) — the safe access pattern
                    targets = mgr.data.get("ssh_targets", {})
                    assert isinstance(targets, dict)
                    assert len(targets) >= 12
            except Exception as exc:
                errors.append(exc)

        def modifier():
            for i in range(10):
                new_cfg = json.loads(dest.read_text(encoding="utf-8"))
                new_cfg["settings"]["max_output_length"] = 50000 + i
                dest.write_text(json.dumps(new_cfg), encoding="utf-8")
                time.sleep(0.05)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        mod_thread = threading.Thread(target=modifier)

        for t in threads:
            t.start()
        mod_thread.start()

        for t in threads:
            t.join()
        mod_thread.join()

        mgr.stop_watcher()
        assert len(errors) == 0, f"Errors during concurrent access: {errors}"


# ---------------------------------------------------------------------------
# Test 8: SSH target field migration (snake_case)
# ---------------------------------------------------------------------------


def test_ssh_target_migration():
    """Verify targets use snake_case 'private_key', not camelCase 'privateKey'."""
    bundled = _load_bundled()

    for tid, tdef in bundled["ssh_targets"].items():
        assert "privateKey" not in tdef, (
            f"Target '{tid}' has camelCase 'privateKey' — should use 'private_key'"
        )
        assert tdef.get("private_key") or tdef.get("password"), (
            f"Target '{tid}' missing required authentication (private_key or password)"
        )

    # Also verify through ConfigManager's get_ssh_target
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / "ssh-mcp-config.json"
        dest.write_text(json.dumps(bundled), encoding="utf-8")
        mgr = ConfigManager(td)

        for tid in ["example-server-1", "example-server-2"]:
            tgt = mgr.get_ssh_target(tid)
            assert tgt is not None, f"get_ssh_target({tid!r}) returned None"
            assert tgt.get("private_key") or tgt.get("password"), (
                f"get_ssh_target({tid!r}) missing auth: {tgt}"
            )
            assert "privateKey" not in tgt, (
                f"get_ssh_target({tid!r}) has camelCase 'privateKey': {tgt}"
            )
