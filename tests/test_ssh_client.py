"""Unit tests for :mod:`lib.ssh_client` — SSHClientManager.

All tests use ``unittest.mock`` to avoid making real SSH connections:
paramiko classes are patched, key files are written to ``tmp_path``,
and connection failures are simulated by raising from the mocked
``get_client``.
"""

from __future__ import annotations

import os
import socket
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from lib.circuit_breaker import CircuitBreaker
from lib.constants import (
    DEFAULT_SSH_PORT,
    DEFAULT_SSH_TIMEOUT_SECONDS,
    PEM_HEADER_OPENSSH,
    PEM_HEADER_PKCS8,
    PEM_HEADER_RSA,
)
from lib.exceptions import (
    SSHAuthenticationError,
    SSHConnectionError,
    SSHTimeoutError,
)
from lib.ssh_client import SSHClientManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _password_target(**overrides) -> dict:
    """Return a password-auth SSH target dict, with optional overrides."""
    target = {
        "host": "10.0.0.1",
        "username": "root",
        "auth": {"type": "password", "password": "secret"},
    }
    target.update(overrides)
    return target


def _key_target(**overrides) -> dict:
    """Return a key-auth SSH target dict, with optional overrides."""
    target = {
        "host": "10.0.0.1",
        "username": "root",
        "auth": {"type": "key", "key_filename": "~/keys/id_ed25519"},
    }
    target.update(overrides)
    return target


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------


class TestKeyLoading:
    """Tests for _load_ssh_key() PEM-header dispatch."""

    @pytest.mark.parametrize(
        ("header", "key_class_name"),
        [
            (PEM_HEADER_OPENSSH, "Ed25519Key"),
            (PEM_HEADER_PKCS8, "Ed25519Key"),
            (PEM_HEADER_RSA, "RSAKey"),
        ],
    )
    def test_header_dispatch_to_key_loader(self, tmp_path, header, key_class_name):
        """Each PEM header routes to the matching paramiko key loader."""
        key_file = tmp_path / "id_key"
        key_file.write_text(f"-----{header}-----\nbase64-body\n", encoding="utf-8")
        manager = SSHClientManager()

        with patch(f"lib.ssh_client.{key_class_name}") as mock_key_cls:
            loaded = manager._load_ssh_key(str(key_file))

        mock_key_cls.from_private_key.assert_called_once()
        assert loaded is mock_key_cls.from_private_key.return_value

    def test_header_line_is_stripped(self, tmp_path):
        """Leading/trailing whitespace on the header line is tolerated."""
        key_file = tmp_path / "id_key"
        key_file.write_text(
            f"  -----{PEM_HEADER_OPENSSH}-----  \nbody\n", encoding="utf-8"
        )
        manager = SSHClientManager()

        with patch("lib.ssh_client.Ed25519Key") as mock_key_cls:
            manager._load_ssh_key(str(key_file))

        mock_key_cls.from_private_key.assert_called_once()

    def test_loader_receives_open_file_object(self, tmp_path):
        """The key loader is handed an open, readable file handle."""
        key_file = tmp_path / "id_key"
        key_file.write_text(f"-----{PEM_HEADER_OPENSSH}-----\nbody\n", encoding="utf-8")
        manager = SSHClientManager()

        with patch("lib.ssh_client.Ed25519Key") as mock_key_cls:
            manager._load_ssh_key(str(key_file))
    
        handle = mock_key_cls.from_private_key.call_args.args[0]
        assert hasattr(handle, "read")
        assert handle.closed  # resource hygiene: file closed after key load

    def test_unsupported_header_raises_value_error(self, tmp_path):
        """An unrecognised PEM header raises ValueError."""
        key_file = tmp_path / "id_key"
        key_file.write_text("-----BEGIN EC PRIVATE KEY-----\nbody\n", encoding="utf-8")
        manager = SSHClientManager()

        with pytest.raises(ValueError, match="Unsupported key format"):
            manager._load_ssh_key(str(key_file))

    def test_missing_key_file_raises_file_not_found(self, tmp_path):
        """A non-existent key file raises FileNotFoundError."""
        manager = SSHClientManager()

        with pytest.raises(FileNotFoundError):
            manager._load_ssh_key(str(tmp_path / "does-not-exist"))


# ---------------------------------------------------------------------------
# get_client
# ---------------------------------------------------------------------------


class TestGetClient:
    """Tests for SSHClientManager.get_client()."""

    def test_password_auth(self):
        """Password auth passes password into connect() and returns the client."""
        manager = SSHClientManager(default_timeout=15)
        target = _password_target()

        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ) as mock_policy:
            client = manager.get_client(target)

        assert client is mock_cls.return_value
        mock_cls.return_value.set_missing_host_key_policy.assert_called_once_with(
            mock_policy.return_value
        )
        mock_cls.return_value.connect.assert_called_once_with(
            hostname="10.0.0.1",
            port=DEFAULT_SSH_PORT,
            username="root",
            timeout=15,
            password="secret",
        )

    def test_password_auth_default_timeout(self):
        """The manager's default timeout is forwarded to connect()."""
        manager = SSHClientManager()
        target = _password_target()

        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ):
            manager.get_client(target)

        mock_cls.return_value.connect.assert_called_once_with(
            hostname="10.0.0.1",
            port=DEFAULT_SSH_PORT,
            username="root",
            timeout=DEFAULT_SSH_TIMEOUT_SECONDS,
            password="secret",
        )

    def test_key_auth_expands_home_and_passes_pkey(self):
        """Key auth expands '~' and passes the loaded pkey to connect()."""
        manager = SSHClientManager()
        target = _key_target(port=2222)
        key_mock = MagicMock()

        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ), patch.object(
            manager, "_load_ssh_key", return_value=key_mock
        ) as mock_load:
            manager.get_client(target)

        mock_load.assert_called_once_with(os.path.expanduser("~/keys/id_ed25519"))
        mock_cls.return_value.connect.assert_called_once_with(
            hostname="10.0.0.1",
            port=2222,
            username="root",
            timeout=DEFAULT_SSH_TIMEOUT_SECONDS,
            pkey=key_mock,
        )

    def test_unsupported_auth_type_raises_value_error(self):
        """An unknown auth type raises ValueError before connecting."""
        manager = SSHClientManager()
        target = {"host": "h", "username": "u", "auth": {"type": "agent"}}

        with pytest.raises(ValueError, match="Unsupported auth type"):
            manager.get_client(target)

    def test_default_port_used_when_missing(self):
        """Missing target port falls back to DEFAULT_SSH_PORT."""
        manager = SSHClientManager()
        target = _password_target()  # no port key

        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ):
            manager.get_client(target)

        kwargs = mock_cls.return_value.connect.call_args.kwargs
        assert kwargs["port"] == DEFAULT_SSH_PORT


# ---------------------------------------------------------------------------
# connect() context manager (task 02b)
# ---------------------------------------------------------------------------


class TestConnect:
    """Tests for SSHClientManager.connect() context-manager behaviour."""

    def test_yields_client_and_closes_on_exit(self):
        """The connected client is yielded and closed on normal exit."""
        manager = SSHClientManager()
        client = MagicMock()
        target = _password_target()

        with patch.object(manager, "get_client", return_value=client):
            with manager.connect(target) as c:
                assert c is client

        client.close.assert_called_once()

    def test_connect_delegates_to_get_client(self):
        """connect() obtains the client via get_client() with the target."""
        manager = SSHClientManager()
        client = MagicMock()
        target = _password_target()

        with patch.object(
            manager, "get_client", return_value=client
        ) as mock_get:
            with manager.connect(target) as c:
                assert c is client

        mock_get.assert_called_once_with(target)

    def test_close_called_when_body_raises(self):
        """client.close() still runs when the with-block raises."""
        manager = SSHClientManager()
        client = MagicMock()
        target = _password_target()

        with patch.object(manager, "get_client", return_value=client):
            with pytest.raises(RuntimeError, match="body failed"):
                with manager.connect(target):
                    raise RuntimeError("body failed")

        client.close.assert_called_once()

    def test_close_errors_are_swallowed(self):
        """A failing client.close() does not mask the original result."""
        manager = SSHClientManager()
        client = MagicMock()
        client.close.side_effect = RuntimeError("close failed")
        target = _password_target()

        with patch.object(manager, "get_client", return_value=client):
            with manager.connect(target) as c:
                assert c is client

    def test_ssh_exception_wrapped_as_ssh_connection_error(self):
        """paramiko.SSHException from get_client is wrapped with host info."""
        manager = SSHClientManager()
        target = _password_target(host="myhost")
        original = paramiko.SSHException("auth failed")

        with patch.object(manager, "get_client", side_effect=original):
            with pytest.raises(SSHConnectionError) as excinfo:
                with manager.connect(target):
                    pass

        assert "myhost" in str(excinfo.value)
        assert "auth failed" in str(excinfo.value)
        assert excinfo.value.__cause__ is original

    def test_oserror_wrapped_as_ssh_connection_error(self):
        """OSError from get_client (e.g. missing key file) is wrapped."""
        manager = SSHClientManager()
        target = _password_target()
        original = OSError("connection reset")

        with patch.object(manager, "get_client", side_effect=original):
            with pytest.raises(SSHConnectionError) as excinfo:
                with manager.connect(target):
                    pass

        assert "connection reset" in str(excinfo.value)
        assert excinfo.value.__cause__ is original

    def test_oserror_from_body_is_wrapped(self):
        """An OSError raised inside the with-block is wrapped too."""
        manager = SSHClientManager()
        client = MagicMock()
        target = _password_target()

        with patch.object(manager, "get_client", return_value=client):
            with pytest.raises(SSHConnectionError):
                with manager.connect(target):
                    raise OSError("socket closed")


class TestRetry:
    """Tests for transient-error retry with exponential backoff."""

    def test_retries_transient_errors(self):
        """A transient failure is retried and ultimately succeeds."""
        manager = SSHClientManager(retry_max_attempts=3)
        client = MagicMock()
        target = _password_target()

        transient = paramiko.SSHException("connection reset")
        with patch.object(
            manager, "_connect_once", side_effect=[transient, client]
        ) as mock_connect:
            result = manager.get_client(target)

        assert result is client
        assert mock_connect.call_count == 2

    def test_transient_failures_all_attempts_raise(self):
        """When every attempt fails transiently, get_client raises."""
        manager = SSHClientManager(retry_max_attempts=3)
        target = _password_target()
        transient = socket.timeout("timed out")

        with patch.object(
            manager, "_connect_once", side_effect=transient
        ) as mock_connect, patch.object(manager, "_sleep_before_retry"):
            with pytest.raises(socket.timeout):
                manager.get_client(target)

        assert mock_connect.call_count == 3

    def test_no_retry_for_auth_failures(self):
        """Authentication failures are permanent and never retried."""
        manager = SSHClientManager(retry_max_attempts=3)
        target = _password_target()
        auth_error = paramiko.AuthenticationException("bad password")

        with patch.object(
            manager, "_connect_once", side_effect=auth_error
        ) as mock_connect:
            with pytest.raises(paramiko.AuthenticationException):
                manager.get_client(target)

        mock_connect.assert_called_once()

    def test_no_retry_for_unsupported_auth_type(self):
        """ValueError (unsupported auth type) is never retried."""
        manager = SSHClientManager(retry_max_attempts=3)
        target = _password_target()
        target["auth"] = {"type": "kerberos"}

        with patch.object(
            manager, "_connect_once", side_effect=ValueError("Unsupported auth type")
        ) as mock_connect:
            with pytest.raises(ValueError):
                manager.get_client(target)

        mock_connect.assert_called_once()

    def test_no_retry_for_permanent_oserror(self):
        """FileNotFoundError (missing key) is permanent and never retried."""
        manager = SSHClientManager(retry_max_attempts=3)
        target = _password_target()

        with patch.object(
            manager, "_connect_once", side_effect=FileNotFoundError("no key")
        ) as mock_connect:
            with pytest.raises(FileNotFoundError):
                manager.get_client(target)

        mock_connect.assert_called_once()

    def test_backoff_delay_grows_exponentially_with_jitter(self):
        """backoff = base * 2^attempt + random(0, base)."""
        manager = SSHClientManager(
            retry_max_attempts=3, retry_backoff_base_seconds=2.0
        )
        with patch("lib.ssh_client.random.uniform", return_value=0.5) as mock_rand:
            assert manager._backoff_delay(0) == 2.0 * 1 + 0.5
            assert manager._backoff_delay(1) == 2.0 * 2 + 0.5
            assert manager._backoff_delay(2) == 2.0 * 4 + 0.5

        assert mock_rand.call_count == 3

    def test_sleep_before_retry_sleeps_for_backoff(self):
        """_sleep_before_retry sleeps for the computed backoff delay."""
        manager = SSHClientManager(
            retry_max_attempts=3, retry_backoff_base_seconds=1.0
        )
        with patch.object(manager, "_backoff_delay", return_value=1.5) as mock_delay, patch(
            "lib.ssh_client.time.sleep"
        ) as mock_sleep:
            manager._sleep_before_retry(1)

        mock_delay.assert_called_once_with(1)
        mock_sleep.assert_called_once_with(1.5)


class TestCircuitBreakerIntegration:
    """Tests for circuit-breaker behaviour inside connect()."""

    def test_success_records_success(self):
        """A clean connection closes the circuit."""
        cb = CircuitBreaker(failure_threshold=2)
        manager = SSHClientManager(circuit_breaker=cb)
        client = MagicMock()
        target = _password_target()
        target_name = manager._target_name(target)

        with patch.object(manager, "get_client", return_value=client):
            with manager.connect(target):
                pass

        assert cb.state(target_name) == CircuitBreaker.CLOSED
        assert cb.failure_count(target_name) == 0

    def test_connection_failure_counts_towards_circuit(self):
        """A failed connection is recorded as a failure on the circuit."""
        cb = CircuitBreaker(failure_threshold=2)
        manager = SSHClientManager(circuit_breaker=cb)
        target = _password_target()
        target_name = manager._target_name(target)

        with patch.object(
            manager, "get_client", side_effect=paramiko.SSHException("down")
        ):
            with pytest.raises(SSHConnectionError):
                with manager.connect(target):
                    pass

        assert cb.failure_count(target_name) == 1
        assert cb.state(target_name) == CircuitBreaker.CLOSED

    def test_open_circuit_blocks_connection(self):
        """When the circuit is open, connect() fails fast."""
        cb = CircuitBreaker(failure_threshold=1)
        manager = SSHClientManager(circuit_breaker=cb)
        target = _password_target()
        target_name = manager._target_name(target)

        # Trip the circuit with a single recorded failure.
        cb.record_failure(target_name)
        assert cb.state(target_name) == CircuitBreaker.OPEN

        with patch.object(manager, "get_client") as mock_get:
            with pytest.raises(SSHConnectionError, match="circuit breaker"):
                with manager.connect(target):
                    pass

        mock_get.assert_not_called()

    def test_half_open_probe_success_closes_circuit(self):
        """A successful probe after the cooldown closes the circuit."""
        with patch(
            "lib.circuit_breaker.time.monotonic", return_value=100.0
        ) as mock_monotonic:
            cb = CircuitBreaker(failure_threshold=1, timeout_seconds=0.001)
            manager = SSHClientManager(circuit_breaker=cb)
            client = MagicMock()
            target = _password_target()
            target_name = manager._target_name(target)

            cb.record_failure(target_name)  # circuit opens at t=100
            assert cb(target_name) is False  # circuit open — blocked

            # Cooldown elapses; connect() itself runs the half-open probe.
            mock_monotonic.return_value = 200.0
            with patch.object(manager, "get_client", return_value=client):
                with manager.connect(target):
                    pass

            assert cb.state(target_name) == CircuitBreaker.CLOSED

    def test_authentication_error_not_recorded_as_circuit_failure(self):
        """Auth failures never count towards opening the circuit."""
        cb = CircuitBreaker(failure_threshold=1)
        manager = SSHClientManager(circuit_breaker=cb)
        target = _password_target()
        target_name = manager._target_name(target)

        with patch.object(
            manager, "get_client", side_effect=paramiko.AuthenticationException("denied")
        ):
            with pytest.raises(SSHAuthenticationError):
                with manager.connect(target):
                    pass

        assert cb.state(target_name) == CircuitBreaker.CLOSED
        assert cb.failure_count(target_name) == 0

    def test_timeout_records_circuit_failure(self):
        """A socket timeout is recorded as a circuit failure."""
        cb = CircuitBreaker(failure_threshold=2)
        manager = SSHClientManager(circuit_breaker=cb)
        target = _password_target()
        target_name = manager._target_name(target)

        with patch.object(
            manager, "get_client", side_effect=socket.timeout("slow")
        ):
            with pytest.raises(SSHTimeoutError):
                with manager.connect(target):
                    pass

        assert cb.failure_count(target_name) == 1
        assert cb.state(target_name) == CircuitBreaker.CLOSED
