"""Verify piping and command chaining against the ACTUAL deployed configuration.

These tests load the real ``config/ssh-mcp-config.json`` (read-only), build an
:class:`~lib.auth.AuthorizationManager` from it, and exercise :meth:`check_command`
directly to confirm that:

* allow-listed commands chained via ``|``, ``&&``, ``||``, or ``;`` are ALLOWED;
* a chained segment that is NOT allow-listed causes the whole command to be DENIED
  (proving the segment recursion in ``check_command`` actually rejects it);
* a chained segment that matches a ``block_pattern`` causes a denial.

Only pure authorization logic is exercised — no SSH and no HTTP.  The deployed
config directory is never modified; a throwaway copy is made in ``tmp_path``
(same pattern as ``tests/test_auth.py::_make_auth_manager``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lib.auth import AuthorizationManager
from lib.config import ConfigManager

# Path to the ACTUAL deployed config, resolved robustly regardless of CWD.
_DEPLOYED_CONFIG_PATH: Path = (
    Path(__file__).resolve().parents[1] / "config" / "ssh-mcp-config.json"
)

# A client IP that matches NO configured network, so only the `default` rules
# and `block_patterns` decide the outcome.
_NON_NETWORK_IP = "10.99.99.99"

# A realistic SSH target present in the deployed config.
_TARGET = "knubbel"

# Commands that are NOT in any allow-list for _TARGET with a non-matching IP.
# (`nc` and `ifconfig` are not in the default list, and the openwebui network —
# which would otherwise cover only extra commands — does not match here.)
_DISALLOWED_CMDS = {"nc", "ifconfig"}


@pytest.fixture(scope="module")
def deployed_auth_manager(tmp_path_factory: pytest.TempPathFactory) -> AuthorizationManager:
    """Build an AuthorizationManager from the ACTUAL deployed config (read-only).

    The production ``config/ssh-mcp-config.json`` is loaded with ``json.load``
    and a copy is written to an isolated temp directory, so the deployed file
    and all production sources stay untouched.  The return value mirrors
    ``tests/test_auth.py::_make_auth_manager``.
    """
    with _DEPLOYED_CONFIG_PATH.open(encoding="utf-8") as fh:
        deployed_cfg = json.load(fh)

    tmp_path = tmp_path_factory.mktemp("deployed-config")
    (tmp_path / "ssh-mcp-config.json").write_text(
        json.dumps(deployed_cfg), encoding="utf-8"
    )
    config_manager = ConfigManager(str(tmp_path))
    return AuthorizationManager(config_manager)


def _assert_cmd(
    auth_manager: AuthorizationManager,
    command: str,
    *,
    expected: bool,
    assert_matched_via_prefix: str | None = None,
    source_ip: str | None = _NON_NETWORK_IP,
    target: str = _TARGET,
) -> None:
    """Check a single command and assert the expected outcome.

    Args:
        auth_manager: AuthorizationManager built from the deployed config.
        command: Raw command string to authorize.
        expected: Expected ``AuthResult.allowed`` value.
        assert_matched_via_prefix: When provided, assert that
            ``AuthResult.matched_via`` starts with this prefix (e.g. ``"blocked:"``).
        source_ip: Client IP; defaults to a non-matching IP.
        target: SSH target ID; defaults to ``knubbel``.
    """
    result = auth_manager.check_command(command, target, source_ip=source_ip)
    assert result.allowed is expected, (
        f"command={command!r}: expected allowed={expected}, got {result.allowed} "
        f"(reason={result.reason!r}, matched_via={result.matched_via!r})"
    )
    if assert_matched_via_prefix is not None:
        assert result.matched_via.startswith(assert_matched_via_prefix), (
            f"command={command!r}: expected matched_via to start with "
            f"{assert_matched_via_prefix!r}, got {result.matched_via!r}"
        )


# ---------------------------------------------------------------------------
# Piping (allowed commands)
# ---------------------------------------------------------------------------


class TestPipingAllowed:
    """Pipes where every segment is allow-listed should be ALLOWED."""

    @pytest.mark.parametrize(
        "commands",
        [
            "docker logs | grep error",
            "uptime | head",
            "cat /etc/hostname | wc -l",
            "ls -la | grep foo",
        ],
    )
    def test_pipe_all_allowed(
        self,
        deployed_auth_manager: AuthorizationManager,
        commands: str,
    ) -> None:
        _assert_cmd(deployed_auth_manager, commands, expected=True)

    def test_stderr_redirect_stripped_before_pipe(
        self, deployed_auth_manager: AuthorizationManager
    ) -> None:
        """A stderr redirect glued to the first segment must be stripped before
        segmentation, so the allow-listed 'docker logs' | 'grep' pipe is allowed
        (regression for redirection-stripping before the allow-chain)."""
        _assert_cmd(
            deployed_auth_manager,
            "docker logs traefik --tail 200 2>&1 | grep -i certificate",
            expected=True,
        )

    def test_pipe_second_segment_not_allowed_denied(
        self, deployed_auth_manager: AuthorizationManager
    ) -> None:
        """A pipe whose second segment is NOT allow-listed is DENIED."""
        for disallowed in sorted(_DISALLOWED_CMDS):
            _assert_cmd(
                deployed_auth_manager,
                f"ls | {disallowed}",
                expected=False,
                assert_matched_via_prefix="denied",
            )

    def test_pipe_segment_matches_block_pattern_denied(
        self, deployed_auth_manager: AuthorizationManager
    ) -> None:
        """A pipe containing a block-pattern command is DENIED."""
        _assert_cmd(
            deployed_auth_manager,
            "echo hi | rm -rf /tmp/x",
            expected=False,
            assert_matched_via_prefix="blocked:",
        )


# ---------------------------------------------------------------------------
# Chaining (allowed commands)
# ---------------------------------------------------------------------------


class TestChainingAllowed:
    """Chains where every segment is allow-listed should be ALLOWED."""

    @pytest.mark.parametrize(
        "commands",
        [
            "ls && cat /etc/hostname",
            "uptime && free",
            "df -h && du -sh /tmp",
            "echo hello; date",
            "hostname || uptime",
        ],
    )
    def test_chain_all_allowed(
        self,
        deployed_auth_manager: AuthorizationManager,
        commands: str,
    ) -> None:
        _assert_cmd(deployed_auth_manager, commands, expected=True)

    def test_chain_later_command_not_allowed_denied(
        self, deployed_auth_manager: AuthorizationManager
    ) -> None:
        """A chain whose later command is NOT allow-listed is DENIED."""
        for disallowed in sorted(_DISALLOWED_CMDS):
            _assert_cmd(
                deployed_auth_manager,
                f"ls && {disallowed}",
                expected=False,
                assert_matched_via_prefix="denied",
            )

    def test_chain_first_command_not_allowed_denied(
        self, deployed_auth_manager: AuthorizationManager
    ) -> None:
        """A chain whose FIRST command is NOT allow-listed is DENIED."""
        for disallowed in sorted(_DISALLOWED_CMDS):
            _assert_cmd(
                deployed_auth_manager,
                f"{disallowed} && uptime",
                expected=False,
                assert_matched_via_prefix="denied",
            )

    def test_chain_segment_matches_block_pattern_denied(
        self, deployed_auth_manager: AuthorizationManager
    ) -> None:
        """A chain containing a block-pattern command is DENIED."""
        _assert_cmd(
            deployed_auth_manager,
            "ls && shutdown -h now",
            expected=False,
            assert_matched_via_prefix="blocked:",
        )
