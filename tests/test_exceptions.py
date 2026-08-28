"""Unit tests for :mod:`lib.exceptions` — the MCPSSHError hierarchy.

Verifies that all application-level exception subclasses inherit
from the single :class:`MCPSSHError` base, are catchable as that base,
and carry their messages / attributes correctly.
"""

from __future__ import annotations

import pytest

from lib.exceptions import (
    AuthorizationError,
    ConfigError,
    ConfigMigrationError,
    ConfigValidationError,
    FileTransferError,
    MCPSSHError,
    PathValidationError,
    RateLimitError,
    SecretsError,
    ServiceUnavailableError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHTimeoutError,
    ShutdownError,
)

# Every concrete application-level exception defined in lib.exceptions.
ALL_SUBCLASSES = [
    ConfigError,
    SecretsError,
    ConfigMigrationError,
    ConfigValidationError,
    SSHConnectionError,
    SSHAuthenticationError,
    SSHTimeoutError,
    AuthorizationError,
    FileTransferError,
    PathValidationError,
    RateLimitError,
    ServiceUnavailableError,
    ShutdownError,
]


class TestExceptionHierarchy:
    """Tests that every subclass belongs to the MCPSSHError family."""

    def test_all_subclasses_inherit_from_mcpssh_error(self):
        """Each subclass is a subclass of MCPSSHError."""
        for exc_cls in ALL_SUBCLASSES:
            assert issubclass(exc_cls, MCPSSHError), exc_cls.__name__

    def test_all_subclasses_are_exceptions(self):
        """Each subclass is ultimately a builtin Exception."""
        for exc_cls in ALL_SUBCLASSES:
            assert issubclass(exc_cls, Exception), exc_cls.__name__

    def test_mcpssh_error_is_exception(self):
        """MCPSSHError itself derives from Exception."""
        assert issubclass(MCPSSHError, Exception)

    def test_each_subclass_catchable_as_base(self):
        """Raising any subclass can be caught as MCPSSHError."""
        for exc_cls in ALL_SUBCLASSES:
            with pytest.raises(MCPSSHError):
                raise exc_cls("boom")

    @pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
    def test_message_preserved(self, exc_cls):
        """str() of each exception exposes the message."""
        err = exc_cls("some message")
        assert str(err) == "some message"
        assert err.args == ("some message",)


class TestMCPSSHError:
    """Tests for the base exception class itself."""

    def test_instantiates_with_message(self):
        err = MCPSSHError("base error")
        assert str(err) == "base error"

    def test_catchable(self):
        with pytest.raises(MCPSSHError):
            raise MCPSSHError("base error")

    def test_no_message_instantiates(self):
        err = MCPSSHError()
        assert str(err) == ""


class TestConfigValidationError:
    """Tests for the attribute-carrying ConfigValidationError subclass."""

    def test_attributes_populated(self):
        err = ConfigValidationError(
            "config invalid",
            errors=["missing 'host'", "bad port"],
            field="host",
        )
        assert err.message == "config invalid"
        assert err.errors == ["missing 'host'", "bad port"]
        assert err.field == "host"
        assert str(err) == "config invalid"

    def test_defaults_when_omitted(self):
        err = ConfigValidationError("simple")
        assert err.message == "simple"
        assert err.errors is None
        assert err.field is None

    def test_field_alias_matches_errors(self):
        """field is a backward-compatible alias for a one-element errors list."""
        err = ConfigValidationError("bad", field="username")
        assert err.field == "username"

    def test_is_mcpssh_error(self):
        with pytest.raises(MCPSSHError):
            raise ConfigValidationError("x")


class TestConcreteSubclassBasics:
    """Spot checks that plain subclasses behave like normal exceptions."""

    def test_config_error(self):
        with pytest.raises(ConfigError, match="io failed"):
            raise ConfigError("io failed")

    def test_ssh_connection_error(self):
        with pytest.raises(SSHConnectionError, match="refused"):
            raise SSHConnectionError("connection refused")

    def test_ssh_authentication_error_is_connection_error(self):
        """SSHAuthenticationError is catchable as SSHConnectionError."""
        with pytest.raises(SSHConnectionError, match="auth failed"):
            raise SSHAuthenticationError("auth failed")

    def test_ssh_timeout_error_is_connection_error(self):
        """SSHTimeoutError is catchable as SSHConnectionError."""
        with pytest.raises(SSHConnectionError, match="timed out"):
            raise SSHTimeoutError("timed out")

    def test_authorization_error(self):
        with pytest.raises(AuthorizationError, match="denied"):
            raise AuthorizationError("command denied")

    def test_path_validation_error_is_file_transfer_error(self):
        """PathValidationError is catchable as FileTransferError."""
        with pytest.raises(FileTransferError, match="traversal"):
            raise PathValidationError("path traversal")

    def test_file_transfer_error(self):
        with pytest.raises(FileTransferError, match="sftp"):
            raise FileTransferError("sftp failure")

    def test_rate_limit_error(self):
        with pytest.raises(RateLimitError, match="too many"):
            raise RateLimitError("too many requests")

    def test_shutdown_error(self):
        with pytest.raises(ShutdownError, match="shutdown"):
            raise ShutdownError("shutdown failed")

    def test_service_unavailable_error(self):
        with pytest.raises(ServiceUnavailableError, match="busy"):
            raise ServiceUnavailableError("too busy")


class TestUserMessage:
    """Tests for the ``user_message`` property on MCPSSHError and subclasses."""

    # -- base class tests ---------------------------------------------------

    def test_base_default_user_message(self):
        """MCPSSHError without explicit user_message returns the class default."""
        err = MCPSSHError("detail")
        assert err.user_message == "An internal error occurred"

    def test_base_explicit_user_message(self):
        """MCPSSHError with explicit user_message returns that value."""
        err = MCPSSHError("detail", user_message="safe")
        assert err.user_message == "safe"

    def test_str_preserves_original_message(self):
        """str() must still return the original message, not the user_message."""
        err = MCPSSHError("detail")
        assert str(err) == "detail"

    # -- parametrized subclass tests ----------------------------------------

    @pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
    def test_subclass_default_user_message_is_nonempty(self, exc_cls):
        """Every subclass defines a non-empty DEFAULT_USER_MESSAGE."""
        assert isinstance(exc_cls.DEFAULT_USER_MESSAGE, str)
        assert len(exc_cls.DEFAULT_USER_MESSAGE) > 0

    @pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
    def test_subclass_default_used_when_no_explicit(self, exc_cls):
        """Without an explicit user_message, the subclass default is returned."""
        err = exc_cls("detail")
        assert err.user_message == exc_cls.DEFAULT_USER_MESSAGE

    @pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
    def test_subclass_explicit_user_message(self, exc_cls):
        """Explicit user_message overrides the subclass default."""
        err = exc_cls("detail", user_message="custom")
        assert err.user_message == "custom"

    @pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
    def test_subclass_str_preserves_original(self, exc_cls):
        """str() of every subclass still returns the original message."""
        err = exc_cls("original msg")
        assert str(err) == "original msg"

    # -- custom __init__ subclasses -----------------------------------------

    def test_config_validation_error_user_message(self):
        """ConfigValidationError uses its own DEFAULT_USER_MESSAGE."""
        err = ConfigValidationError("msg", errors=["e"], field="f")
        assert err.user_message == "Configuration validation failed"

    def test_config_validation_error_explicit_user_message(self):
        """ConfigValidationError respects explicit user_message."""
        err = ConfigValidationError("msg", user_message="custom")
        assert err.user_message == "custom"

    def test_service_unavailable_error_user_message(self):
        """ServiceUnavailableError uses its own DEFAULT_USER_MESSAGE."""
        err = ServiceUnavailableError("msg", status_code=503)
        assert err.user_message == "Service temporarily unavailable"

    def test_service_unavailable_error_explicit_user_message(self):
        """ServiceUnavailableError respects explicit user_message."""
        err = ServiceUnavailableError("msg", status_code=503, user_message="custom")
        assert err.user_message == "custom"
