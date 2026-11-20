"""Unit tests for :mod:`lib.sudoers` and the path-resolution helper.

The module under test is pure: grant collection reads a config dict,
rendering takes already-resolved paths.  Only
:func:`lib.ssh_operations.resolve_command_paths` touches the network, and
it is exercised with a mocked ``SSHClientManager``.
"""

from __future__ import annotations

import datetime as dt
import getpass
import json
import re
import shutil
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from lib.config import ConfigManager
from lib.constants import SUDOERS_ALIAS_LINE_WIDTH
from lib.exceptions import SSHConnectionError
from lib.ssh_operations import _build_resolve_script, resolve_command_paths
from lib.sudoers import (
    collect_sudo_grants,
    format_aliases,
    is_command_name,
    is_sudoers_path,
    render_sudoers,
    sudoers_alias,
    sudoers_filename,
)
from lib.types import SudoersDocument  # noqa: F401  (documents the contract)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _allowed_commands(**layers) -> dict:
    """Build an ``allowed_commands`` section from layer keyword lists."""
    return {
        "default": layers.get("default", []),
        "api_keys": layers.get("api_keys", []),
        "networks": layers.get("networks", []),
    }


# ---------------------------------------------------------------------------
# is_command_name / is_sudoers_path
# ---------------------------------------------------------------------------


class TestValidators:
    """Tests for the value validators used before rendering."""

    @pytest.mark.parametrize(
        "name", ["ls", "docker", "ha", "systemctl", "python3.13", "foo_bar", "a+b"]
    )
    def test_valid_command_names(self, name):
        """Plain command names are accepted."""
        assert is_command_name(name) is True

    @pytest.mark.parametrize(
        "name", ["", "ls -la", "/usr/bin/docker", "sudo ls", "a b", "a;b", "*"]
    )
    def test_invalid_command_names(self, name):
        """Paths, arguments, metacharacters and the wildcard are rejected."""
        assert is_command_name(name) is False

    @pytest.mark.parametrize(
        "path", ["/usr/bin/docker", "/usr/local/bin/ha", "/sbin/iptables"]
    )
    def test_valid_paths(self, path):
        """Absolute paths without spaces are accepted."""
        assert is_sudoers_path(path) is True

    @pytest.mark.parametrize(
        "path", ["", "usr/bin/docker", "/usr/bin/do cker", "/tmp/x y", "*"]
    )
    def test_invalid_paths(self, path):
        """Relative paths and paths with whitespace are rejected."""
        assert is_sudoers_path(path) is False


# ---------------------------------------------------------------------------
# collect_sudo_grants
# ---------------------------------------------------------------------------


class TestCollectSudoGrants:
    """Tests for collect_sudo_grants()."""

    def test_single_default_rule(self):
        """Only the commands named in sudo_allowed contribute."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[
                    {
                        "targets": ["*"],
                        "commands": ["ls", "docker"],
                        "sudo_allowed": ["docker"],
                    }
                ]
            ),
            "web",
        )

        assert result["commands"] == ["docker"]
        assert result["skipped"] == []
        assert result["invalid"] == []

    def test_rule_without_sudo_allowed_contributes_nothing(self):
        """A rule that does not grant sudo contributes nothing."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[{"targets": ["*"], "commands": ["ls", "uptime"]}]
            ),
            "web",
        )

        assert result["commands"] == []

    def test_union_of_all_three_layers(self):
        """Default, API-key and network rules all contribute."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[
                    {
                        "targets": ["*"],
                        "commands": ["ls"],
                        "sudo_allowed": ["ls"],
                    }
                ],
                api_keys=[
                    {
                        "name": "deploy",
                        "rules": [
                            {
                                "targets": ["web"],
                                "commands": ["docker"],
                                "sudo_allowed": ["docker"],
                            }
                        ],
                    }
                ],
                networks=[
                    {
                        "name": "lan",
                        "rules": [
                            {
                                "targets": ["*"],
                                "commands": ["systemctl"],
                                "sudo_allowed": ["systemctl"],
                            }
                        ],
                    }
                ],
            ),
            "web",
        )

        assert result["commands"] == ["docker", "ls", "systemctl"]

    def test_rule_for_other_target_is_ignored(self):
        """Rules that do not target the requested target are skipped."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[
                    {
                        "targets": ["db"],
                        "commands": ["psql"],
                        "sudo_allowed": ["psql"],
                    }
                ]
            ),
            "web",
        )

        assert result["commands"] == []

    def test_wildcard_sudo_allowed_expands_to_all_commands(self):
        """``sudo_allowed: ["*"]`` grants every command of the rule."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[
                    {
                        "targets": ["*"],
                        "commands": ["ls", "cat"],
                        "sudo_allowed": ["*"],
                    }
                ]
            ),
            "web",
        )

        assert result["commands"] == ["cat", "ls"]

    def test_unrestricted_rule_is_skipped(self):
        """``commands: ["*"]`` plus ``sudo_allowed: ["*"]`` never emits ALL."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[
                    {
                        "targets": ["*"],
                        "commands": ["*"],
                        "sudo_allowed": ["*"],
                    }
                ]
            ),
            "web",
        )

        assert result["commands"] == []
        assert result["skipped"] == ["default: sudo for every command"]

    def test_skipped_rule_is_labelled_with_key_name(self):
        """The label says which API key granted sudo on everything."""
        result = collect_sudo_grants(
            _allowed_commands(
                api_keys=[
                    {
                        "name": "root-key",
                        "rules": [
                            {
                                "targets": ["web"],
                                "commands": ["*"],
                                "sudo_allowed": ["*"],
                            }
                        ],
                    }
                ]
            ),
            "web",
        )

        assert result["skipped"] == ["api_keys/root-key: sudo for every command"]

    def test_deduplicates_and_sorts(self):
        """The same command from several layers appears once, sorted."""
        rule = {
            "targets": ["*"],
            "commands": ["zeta", "alpha"],
            "sudo_allowed": ["alpha"],
        }
        result = collect_sudo_grants(
            _allowed_commands(
                default=[rule],
                api_keys=[{"name": "k", "rules": [rule]}],
                networks=[{"name": "n", "rules": [rule]}],
            ),
            "web",
        )

        assert result["commands"] == ["alpha"]

    def test_sudo_allowed_outside_commands_is_dropped(self):
        """A hand-edited rule cannot grant sudo for a command it denies."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[
                    {
                        "targets": ["*"],
                        "commands": ["ls"],
                        "sudo_allowed": ["ls", "rm"],
                    }
                ]
            ),
            "web",
        )

        assert result["commands"] == ["ls"]

    def test_non_command_values_are_reported_invalid(self):
        """Values that are not command names are reported, not rendered."""
        result = collect_sudo_grants(
            _allowed_commands(
                default=[
                    {
                        "targets": ["*"],
                        "commands": ["/usr/bin/docker", "docker ps"],
                        "sudo_allowed": ["*"],
                    }
                ]
            ),
            "web",
        )

        assert result["commands"] == []
        assert result["invalid"] == ["/usr/bin/docker", "docker ps"]

    def test_malformed_layers_do_not_raise(self):
        """Entries of the wrong shape are ignored."""
        result = collect_sudo_grants(
            {"default": ["not-a-dict"], "api_keys": [None], "networks": "x"},
            "web",
        )

        assert result["commands"] == []


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------


class TestNaming:
    """Tests for sudoers_filename() and sudoers_alias()."""

    def test_plain_target(self):
        """A simple target keeps its name."""
        assert sudoers_filename("web") == "mcp-ssh-web"
        assert sudoers_alias("web") == "SSH_MCP_WEB"

    def test_dots_are_replaced(self):
        """Dots would make sudo ignore the file, so they become underscores."""
        assert sudoers_filename("web-1.prod") == "mcp-ssh-web-1_prod"

    def test_other_unsafe_characters_are_replaced(self):
        """Spaces, slashes and colons are replaced too."""
        assert sudoers_filename("a b/c:d") == "mcp-ssh-a_b_c_d"

    def test_alias_is_upper_case(self):
        """The alias name is upper case and keeps the sanitized target."""
        assert sudoers_alias("web-1.prod") == "SSH_MCP_WEB_1_PROD"

    def test_alias_drops_characters_sudo_rejects(self):
        """sudo only accepts [A-Z][A-Z0-9_]* for an alias name."""
        for target in ("eli-kiosk", "web-1.prod", "a b/c:d"):
            alias = sudoers_alias(target)
            assert re.fullmatch(r"[A-Z][A-Z0-9_]*", alias), alias
        assert sudoers_alias("eli-kiosk") == "SSH_MCP_ELI_KIOSK"


# ---------------------------------------------------------------------------
# format_aliases
# ---------------------------------------------------------------------------


class TestFormatAliases:
    """Tests for format_aliases()."""

    def test_short_list_fits_one_line(self):
        """A short alias stays on a single line under the plain name."""
        names, lines = format_aliases(
            "SSH_MCP_WEB", ["/usr/bin/ls *", "/usr/bin/cat *"]
        )

        assert names == ["SSH_MCP_WEB"]
        assert lines == [
            "Cmnd_Alias SSH_MCP_WEB = /usr/bin/ls *, /usr/bin/cat *"
        ]

    def test_long_list_splits_into_numbered_aliases(self):
        """sudoers has no continuation, so long lists become numbered aliases."""
        entries = [f"/usr/bin/command{i} *" for i in range(6)]

        names, lines = format_aliases("SSH_MCP_WEB", entries)

        assert len(names) > 1
        assert names == [f"SSH_MCP_WEB_{i}" for i in range(1, len(names) + 1)]
        assert len(lines) == len(names)
        for name, line in zip(names, lines):
            assert line.startswith(f"Cmnd_Alias {name} = ")

    def test_no_line_contains_a_continuation(self):
        """A backslash would be a syntax error — no line may carry one."""
        entries = [f"/usr/bin/command{i} *" for i in range(40)]

        _, lines = format_aliases("SSH_MCP_WEB", entries)

        for line in lines:
            assert "\\" not in line

    def test_lines_stay_within_the_preferred_width(self):
        """Every generated definition stays readable."""
        entries = [f"/usr/bin/command{i} *" for i in range(20)]

        _, lines = format_aliases("SSH_MCP_WEB", entries)

        assert len(lines) > 1
        for line in lines:
            assert len(line) <= SUDOERS_ALIAS_LINE_WIDTH

    def test_alias_names_match_the_sudo_lexer(self):
        """Only [A-Z][A-Z0-9_]* is a legal alias name."""
        entries = [f"/usr/bin/command{i} *" for i in range(20)]

        names, _ = format_aliases("SSH_MCP_WEB", entries)

        for name in names:
            assert re.fullmatch(r"[A-Z][A-Z0-9_]*", name), name

    def test_every_entry_appears_exactly_once(self):
        """Splitting must not drop or duplicate a command."""
        entries = [f"/usr/bin/command{i} *" for i in range(12)]

        _, lines = format_aliases("SSH_MCP_WEB", entries)

        rendered = ", ".join(line.split(" = ", 1)[1] for line in lines)
        assert rendered.split(", ") == entries

    def test_comma_only_between_entries(self):
        """Commas separate entries only."""
        _, lines = format_aliases("ALIAS", ["/bin/a *", "/bin/b *"])
        assert not lines[-1].rstrip().endswith(",")
        assert lines == ["Cmnd_Alias ALIAS = /bin/a *, /bin/b *"]

    def test_empty_entries_produce_nothing(self):
        """No entries means no definition and no alias to reference."""
        assert format_aliases("ALIAS", []) == ([], [])


# ---------------------------------------------------------------------------
# render_sudoers
# ---------------------------------------------------------------------------


class TestRenderSudoers:
    """Tests for render_sudoers()."""

    def _render(self, **overrides):
        kwargs = {
            "target": "web",
            "username": "deploy",
            "host": "10.0.0.5",
            "resolved": [("docker", "/usr/bin/docker")],
            "unresolved": [],
            "skipped": [],
            "generated_at": dt.datetime(2026, 11, 20, 12, 0, tzinfo=dt.timezone.utc),
        }
        kwargs.update(overrides)
        return render_sudoers(**kwargs)

    def test_header_names_target_user_and_host(self):
        """The header identifies what the file was generated for."""
        content = self._render()

        assert "# Generated by mcp-ssh for target web (10.0.0.5)" in content
        assert "# User: deploy" in content
        assert "# Generated: 2026-11-20 12:00:00Z" in content

    def test_alias_and_user_line(self):
        """The alias lists the path with a wildcard; the user line grants it."""
        content = self._render(
            resolved=[
                ("docker", "/usr/bin/docker"),
                ("ha", "/usr/local/bin/ha"),
            ]
        )

        assert (
            "Cmnd_Alias SSH_MCP_WEB = "
            "/usr/bin/docker *, /usr/local/bin/ha *" in content
        )
        assert "deploy ALL = (root) NOPASSWD: SSH_MCP_WEB" in content

    def test_install_instructions_are_in_the_file(self):
        """The operator has the exact install commands in the file."""
        content = self._render()

        assert "visudo -c -f mcp-ssh-web" in content
        assert "install -m 0440 -o root -g root mcp-ssh-web" in content
        assert "/etc/sudoers.d/mcp-ssh-web" in content

    def test_long_list_is_split_and_fully_referenced(self):
        """A long list becomes numbered aliases, all named in the user line."""
        resolved = [
            (f"cmd{i}", f"/usr/bin/command{i}") for i in range(20)
        ]

        content = self._render(resolved=resolved)

        assert "\\" not in content
        definition_names = [
            line.split(" = ", 1)[0].removeprefix("Cmnd_Alias ")
            for line in content.splitlines()
            if line.startswith("Cmnd_Alias SSH_MCP_WEB_")
        ]
        assert len(definition_names) > 1
        user_line = next(
            line for line in content.splitlines() if line.startswith("deploy ALL")
        )
        assert user_line == (
            "deploy ALL = (root) NOPASSWD: {aliases}".format(
                aliases=", ".join(definition_names)
            )
        )
        for index, (_, path) in enumerate(resolved):
            assert f"{path} *" in content, index

    def test_unresolved_commands_are_commented(self):
        """A command that did not resolve is noted, not rendered."""
        content = self._render(
            resolved=[("docker", "/usr/bin/docker")],
            unresolved=["ha"],
        )

        assert "# not found on 10.0.0.5: ha" in content
        assert "ha *" not in content

    def test_skipped_rules_are_commented(self):
        """Skipped unrestricted rules are recorded in the file."""
        content = self._render(skipped=["default: sudo for every command"])

        assert "# skipped: default: sudo for every command" in content

    def test_empty_resolution_has_no_user_line(self):
        """Without a resolved path there is no user specification."""
        content = self._render(resolved=[], unresolved=["docker"])

        assert "deploy ALL" not in content
        assert "SSH_MCP_WEB" not in content
        assert "# No sudo command could be resolved on this host." in content
        assert "# not found on 10.0.0.5: docker" in content

    def test_ends_with_single_newline(self):
        """The document ends with exactly one newline."""
        content = self._render()

        assert content.endswith("\n")
        assert not content.endswith("\n\n")


# ---------------------------------------------------------------------------
# Parser check — the real visudo, when it is installed
# ---------------------------------------------------------------------------


def _visudo_check(text: str) -> subprocess.CompletedProcess:
    """Parse *text* with the system ``visudo``; skip when unavailable.

    Args:
        text: A sudoers document.

    Returns:
        The completed process, so callers can assert on the exit code.
    """
    exe = shutil.which("visudo")
    if exe is None:
        pytest.skip("visudo is not installed")
    return subprocess.run(
        [exe, "-c", "-f", "-"],
        input=text,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestParserAcceptsOutput:
    """Feed the rendered document to a real sudoers parser.

    sudoers has no line-continuation character and needs the ``Cmnd_Alias``
    keyword, so hand-written expectations can be wrong in ways only a parser
    catches.  These tests fail on a syntactically invalid document.
    """

    def _document(self, target: str, commands: list[str]) -> str:
        return render_sudoers(
            target=target,
            username=getpass.getuser(),
            host="10.0.0.5",
            resolved=[(c, f"/usr/bin/{c}") for c in commands],
            unresolved=[],
            skipped=[],
            generated_at=dt.datetime(2026, 11, 20, 12, 0, tzinfo=dt.timezone.utc),
        )

    def test_single_alias_document_parses(self):
        """A short command list yields valid sudoers."""
        result = _visudo_check(self._document("web", ["ls", "cat"]))

        assert result.returncode == 0, result.stdout + result.stderr

    def test_split_document_parses(self):
        """Numbered aliases are valid sudoers, and the user line names them."""
        commands = [f"cmd{i}" for i in range(20)]

        result = _visudo_check(self._document("web", commands))

        assert result.returncode == 0, result.stdout + result.stderr

    def test_dotted_and_hyphenated_target_parses(self):
        """A target name sudo cannot spell is sanitized into a valid alias."""
        result = _visudo_check(
            self._document("web-1.prod", ["ls", "cat"])
        )

        assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# _build_resolve_script / resolve_command_paths
# ---------------------------------------------------------------------------


class TestBuildResolveScript:
    """Tests for the shell script that looks up command paths."""

    def test_names_are_quoted(self):
        """Command names are shell-quoted into the loop."""
        script = _build_resolve_script(["ls", "python3.13"])

        assert "for c in ls python3.13; do" in script
        assert "command -v" in script
        assert "printf '%s\\t%s\\n'" in script

    def test_suspicious_names_are_quoted_not_interpolated(self):
        """A name with metacharacters cannot break out of the loop."""
        script = _build_resolve_script(["a; rm -rf /"])

        assert "'a; rm -rf /'" in script


class TestResolveCommandPaths:
    """Tests for resolve_command_paths() with a mocked SSH client."""

    def _managers(self, tmp_path):
        """Create a ConfigManager plus a mocked SSHClientManager."""
        config = {
            "version": 1,
            "ssh_targets": {
                "web": {
                    "host": "10.0.0.5",
                    "port": 22,
                    "username": "deploy",
                    "password": "pw",
                }
            },
            "block_patterns": [],
            "allowed_commands": {
                "default": [{"targets": ["*"], "commands": ["ls"]}],
                "api_keys": [],
                "networks": [],
            },
            "settings": {
                "max_output_length": 50000,
                "command_timeout_max": 120,
            },
        }
        (tmp_path / "ssh-mcp-config.json").write_text(json.dumps(config))
        return ConfigManager(str(tmp_path)), MagicMock()

    def _client(self, stdout: bytes, exit_code: int = 0):
        """Return a mocked paramiko client answering exec_command."""
        client = MagicMock()
        stdin = MagicMock()
        out = MagicMock()
        err = MagicMock()
        out.read.return_value = stdout
        err.read.return_value = b""
        out.channel.recv_exit_status.return_value = exit_code
        client.exec_command.return_value = (stdin, out, err)
        return client

    def test_resolves_paths_from_output(self, tmp_path):
        """``name<TAB>path`` lines become the result mapping."""
        config_mgr, ssh_mgr = self._managers(tmp_path)
        client = self._client(b"docker\t/usr/bin/docker\nha\t\n")
        ssh_mgr.connect.return_value.__enter__ = MagicMock(return_value=client)
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch("lib.ssh_operations.os.path.exists", return_value=True):
            result = resolve_command_paths(
                ssh_mgr, config_mgr, "web", "/app/ssh_key", ["docker", "ha"]
            )

        assert result == {"docker": "/usr/bin/docker", "ha": None}

    def test_empty_command_list_returns_empty_mapping(self, tmp_path):
        """Nothing to resolve means no connection."""
        config_mgr, ssh_mgr = self._managers(tmp_path)

        assert resolve_command_paths(
            ssh_mgr, config_mgr, "web", "/app/ssh_key", []
        ) == {}
        ssh_mgr.connect.assert_not_called()

    def test_unknown_target_raises_connection_error(self, tmp_path):
        """An unknown target is rejected before connecting."""
        config_mgr, ssh_mgr = self._managers(tmp_path)

        with pytest.raises(SSHConnectionError):
            resolve_command_paths(
                ssh_mgr, config_mgr, "nope", "/app/ssh_key", ["ls"]
            )
