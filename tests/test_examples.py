"""Automated validation tests for the ``examples/`` directory.

Covers:
- example config files: ``$schema`` key present, pass Draft 2020-12 validation,
  and load through ``ConfigManager``
- Python client example: compiles without syntax errors
- curl-examples.sh: bash syntax, shellcheck, all six tools listed, deny demo
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import py_compile
from pathlib import Path

import pytest

from lib.config import ConfigManager

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "config.schema.json"
EXAMPLES_DIR = REPO_ROOT / "examples"
CURL_SCRIPT = EXAMPLES_DIR / "curl-examples.sh"
MCP_CLIENT_PY = EXAMPLES_DIR / "mcp-client-example.py"

# The six MCP tool names that must appear in the curl-examples script.
ALL_TOOL_NAMES = [
    "ssh_list_servers",
    "ssh_list_allowed_commands",
    "ssh_execute_command",
    "ssh_check_connection",
    "ssh_download_file",
    "ssh_upload_file",
]


def _load_schema() -> dict:
    """Load and decode the hand-written schema as JSON."""
    with SCHEMA_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def _write_config(tmpdir: str, config_dict: dict) -> str:
    """Write *config_dict* as ``ssh-mcp-config.json`` inside *tmpdir*."""
    conf_path = Path(tmpdir) / "ssh-mcp-config.json"
    conf_path.write_text(json.dumps(config_dict), encoding="utf-8")
    return str(conf_path)


class TestExampleConfigs:
    """Validate every ``examples/config-*.json`` against the schema."""

    @pytest.fixture(params=sorted(EXAMPLES_DIR.glob("config-*.json")))
    def config_path(self, request: pytest.FixtureRequest) -> Path:
        """Yield each example config path."""
        return request.param

    @pytest.fixture()
    def config_dict(self, config_path: Path) -> dict:
        """Load the example config as a dict."""
        with config_path.open(encoding="utf-8") as fh:
            return json.load(fh)

    def test_has_schema_key(self, config_path: Path, config_dict: dict) -> None:
        """Each example config must carry a ``$schema`` key."""
        assert "$schema" in config_dict, (
            f"{config_path.name} is missing the $schema key"
        )

    def test_passes_draft_2020_12(self, config_dict: dict) -> None:
        """Each example config must validate under Draft 2020-12."""
        jsonschema = pytest.importorskip("jsonschema")
        schema = _load_schema()
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(config_dict)

    def test_loads_through_config_manager(
        self, config_path: Path, config_dict: dict
    ) -> None:
        """Each example must load through ConfigManager (without ``$schema``)."""
        clean = {k: v for k, v in config_dict.items() if k != "$schema"}
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_config(tmpdir, clean)
            mgr = ConfigManager(tmpdir)


class TestBrokenConfigRejected:
    """A deliberately invalid config must fail ConfigManager loading."""

    def test_broken_config_fails(self) -> None:
        """A config missing required keys is rejected."""
        broken = {"version": 1}
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_config(tmpdir, broken)
            with pytest.raises(Exception):
                ConfigManager(tmpdir)


class TestMCPClientExampleCompiles:
    """The Python MCP client example must be syntactically valid."""

    def test_compiles(self) -> None:
        """``mcp-client-example.py`` compiles without syntax errors."""
        py_compile.compile(str(MCP_CLIENT_PY), doraise=True)


class TestCurlExamplesSyntax:
    """The curl-examples shell script must have valid bash syntax."""

    def test_bash_syntax(self) -> None:
        """``bash -n`` (syntax check) passes on the script."""
        subprocess.run(
            ["bash", "-n", str(CURL_SCRIPT)],
            check=True,
        )

    @pytest.mark.skipif(
        not shutil.which("shellcheck"),
        reason="shellcheck not installed",
    )
    def test_shellcheck(self) -> None:
        """shellcheck reports no warnings on the script."""
        subprocess.run(
            ["shellcheck", str(CURL_SCRIPT)],
            check=True,
        )


class TestCurlExamplesCoverage:
    """The curl-examples script covers all six tools and the deny demo."""

    _script_text: str | None = None

    @classmethod
    def _get_script_text(cls) -> str:
        """Read the curl-examples script as a single string (cached)."""
        if cls._script_text is None:
            cls._script_text = CURL_SCRIPT.read_text(encoding="utf-8")
        return cls._script_text

    @pytest.mark.parametrize("tool_name", ALL_TOOL_NAMES)
    def test_covers_tool(self, tool_name: str) -> None:
        """Each of the six tools must appear in the script."""
        assert tool_name in self._get_script_text(), (
            f"Tool {tool_name!r} not found in curl-examples.sh"
        )

    def test_has_deny_demo(self) -> None:
        """The script must include the authorization-deny demo."""
        assert "Authorization-deny demo" in self._get_script_text()
