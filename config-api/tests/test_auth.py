"""Unit tests for config_api.auth — Bearer token and session cookie auth.

Tests cover:
- load_token() reading from CONFIG_API_TOKEN env var
- load_token() raising RuntimeError when unset/empty
- get_token() returning the loaded token
- get_token() raising RuntimeError when not loaded
- verify_token() accepting valid Bearer tokens
- verify_token() rejecting invalid Bearer tokens with 401
- verify_token() rejecting missing Authorization header with 401
- verify_token() accepting valid session cookies
- verify_token() rejecting expired session cookies
- verify_token() rejecting unknown session cookies
- create_session() generating and storing session IDs
- validate_session() checking existence and expiry
- revoke_session() removing sessions
- cleanup_expired_sessions() evicting stale entries
"""

from __future__ import annotations

import importlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from config_api import auth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reload_auth() -> None:
    """Reload the auth module to reset module-level state."""
    importlib.reload(auth)


def _make_request(cookies: dict[str, str] | None = None) -> MagicMock:
    """Create a mock Starlette Request with optional cookies."""
    request = MagicMock()
    request.cookies = cookies or {}
    return request


# ---------------------------------------------------------------------------
# load_token
# ---------------------------------------------------------------------------


class TestLoadToken:
    """Tests for load_token()."""

    def setup_method(self) -> None:
        """Reset module state before each test."""
        _reload_auth()

    def test_loads_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Token is read from CONFIG_API_TOKEN env var."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "my-secret-token")
        result = auth.load_token()
        assert result == "my-secret-token"

    def test_strips_whitespace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Leading/trailing whitespace is stripped."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "  padded-token  ")
        result = auth.load_token()
        assert result == "padded-token"

    def test_raises_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """RuntimeError raised when CONFIG_API_TOKEN is not set."""
        monkeypatch.delenv("CONFIG_API_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="CONFIG_API_TOKEN"):
            auth.load_token()

    def test_raises_when_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """RuntimeError raised when CONFIG_API_TOKEN is empty string."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "")
        with pytest.raises(RuntimeError, match="CONFIG_API_TOKEN"):
            auth.load_token()

    def test_raises_when_whitespace_only(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """RuntimeError raised when CONFIG_API_TOKEN is only whitespace."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "   ")
        with pytest.raises(RuntimeError, match="CONFIG_API_TOKEN"):
            auth.load_token()

    def test_stores_in_module_variable(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After load_token(), the module-level _token is set."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "stored-token")
        auth.load_token()
        assert auth._token == "stored-token"


# ---------------------------------------------------------------------------
# get_token
# ---------------------------------------------------------------------------


class TestGetToken:
    """Tests for get_token()."""

    def setup_method(self) -> None:
        """Reset module state before each test."""
        _reload_auth()

    def test_returns_loaded_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns the token after load_token() has been called."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "loaded-token")
        auth.load_token()
        assert auth.get_token() == "loaded-token"

    def test_raises_when_not_loaded(self) -> None:
        """RuntimeError raised if load_token() has not been called."""
        with pytest.raises(RuntimeError, match="not loaded"):
            auth.get_token()


# ---------------------------------------------------------------------------
# verify_token — Bearer header
# ---------------------------------------------------------------------------


class TestVerifyTokenBearer:
    """Tests for verify_token() with Bearer header authentication."""

    def setup_method(self) -> None:
        """Reset module state and load a known token."""
        _reload_auth()

    def _make_credentials(self, token: str) -> HTTPAuthorizationCredentials:
        """Create an HTTPAuthorizationCredentials mock."""
        return HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token,
        )

    @pytest.mark.asyncio
    async def test_valid_token_accepted(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A token matching the loaded token is accepted."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "correct-token")
        auth.load_token()
        creds = self._make_credentials("correct-token")
        request = _make_request()
        result = await auth.verify_token(request, credentials=creds)
        assert result == "correct-token"

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A token not matching the loaded token raises 401."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "correct-token")
        auth.load_token()
        creds = self._make_credentials("wrong-token")
        request = _make_request()
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(request, credentials=creds)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "WWW-Authenticate" in exc_info.value.headers
        assert exc_info.value.headers["WWW-Authenticate"] == "Bearer"

    @pytest.mark.asyncio
    async def test_error_detail_no_token_leak(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error detail must not contain the expected token value."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "super-secret-value")
        auth.load_token()
        creds = self._make_credentials("wrong")
        request = _make_request()
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(request, credentials=creds)
        assert "super-secret-value" not in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_empty_provided_token_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty provided token is rejected."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "real-token")
        auth.load_token()
        creds = self._make_credentials("")
        request = _make_request()
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(request, credentials=creds)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_timing_safe_comparison(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """verify_token uses hmac.compare_digest (timing-safe)."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "token")
        auth.load_token()
        creds = self._make_credentials("token")
        request = _make_request()
        with patch("config_api.auth.hmac") as mock_hmac:
            mock_hmac.compare_digest.return_value = True
            result = await auth.verify_token(request, credentials=creds)
            mock_hmac.compare_digest.assert_called_once_with("token", "token")
            assert result == "token"

    @pytest.mark.asyncio
    async def test_no_cookie_no_header_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing both cookie and Bearer header raises 401."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "real-token")
        auth.load_token()
        request = _make_request()
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(request, credentials=None)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# verify_token — session cookie
# ---------------------------------------------------------------------------


class TestVerifyTokenSession:
    """Tests for verify_token() with session cookie authentication."""

    def setup_method(self) -> None:
        """Reset module state and load a known token."""
        _reload_auth()

    @pytest.mark.asyncio
    async def test_valid_session_cookie_accepted(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid, non-expired session cookie is accepted."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "the-token")
        auth.load_token()
        session_id = auth.create_session()
        request = _make_request(
            cookies={auth.CONFIG_API_SESSION_COOKIE_NAME: session_id},
        )
        result = await auth.verify_token(request, credentials=None)
        assert result == "the-token"

    @pytest.mark.asyncio
    async def test_expired_session_cookie_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An expired session cookie is rejected (falls through to Bearer)."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "the-token")
        auth.load_token()
        # Manually insert an expired session.
        auth._sessions["old-session"] = (
            time.time() - auth.CONFIG_API_SESSION_MAX_AGE_SECONDS - 10
        )
        request = _make_request(
            cookies={auth.CONFIG_API_SESSION_COOKIE_NAME: "old-session"},
        )
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(request, credentials=None)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_unknown_session_cookie_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unknown session cookie is rejected."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "the-token")
        auth.load_token()
        request = _make_request(
            cookies={auth.CONFIG_API_SESSION_COOKIE_NAME: "bogus-id"},
        )
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(request, credentials=None)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_session_cookie_takes_precedence(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When both cookie and Bearer header are valid, cookie wins."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "the-token")
        auth.load_token()
        session_id = auth.create_session()
        request = _make_request(
            cookies={auth.CONFIG_API_SESSION_COOKIE_NAME: session_id},
        )
        creds = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials="the-token",
        )
        result = await auth.verify_token(request, credentials=creds)
        assert result == "the-token"


# ---------------------------------------------------------------------------
# create_session
# ---------------------------------------------------------------------------


class TestCreateSession:
    """Tests for create_session()."""

    def setup_method(self) -> None:
        """Reset module state before each test."""
        _reload_auth()

    def test_returns_hex_string(self) -> None:
        """Session ID is a valid hex string of expected length."""
        session_id = auth.create_session()
        assert isinstance(session_id, str)
        # token_hex(n) produces 2*n hex characters.
        expected_len = auth.CONFIG_API_SESSION_ID_LENGTH * 2
        assert len(session_id) == expected_len
        # Must be valid hex.
        int(session_id, 16)

    def test_stores_in_sessions_dict(self) -> None:
        """Session ID is stored in the _sessions dict with a timestamp."""
        session_id = auth.create_session()
        assert session_id in auth._sessions
        assert isinstance(auth._sessions[session_id], float)

    def test_unique_ids(self) -> None:
        """Two consecutive calls produce different session IDs."""
        id1 = auth.create_session()
        id2 = auth.create_session()
        assert id1 != id2

    def test_timestamp_is_recent(self) -> None:
        """The stored timestamp is close to time.time()."""
        before = time.time()
        session_id = auth.create_session()
        after = time.time()
        created = auth._sessions[session_id]
        assert before <= created <= after


# ---------------------------------------------------------------------------
# validate_session
# ---------------------------------------------------------------------------


class TestValidateSession:
    """Tests for validate_session()."""

    def setup_method(self) -> None:
        """Reset module state before each test."""
        _reload_auth()

    def test_returns_true_for_valid_session(self) -> None:
        """A freshly created session is valid."""
        session_id = auth.create_session()
        assert auth.validate_session(session_id) is True

    def test_returns_false_for_unknown_id(self) -> None:
        """An unknown session ID returns False."""
        assert auth.validate_session("does-not-exist") is False

    def test_returns_false_for_expired_session(self) -> None:
        """An expired session returns False and is removed from the store."""
        session_id = auth.create_session()
        # Backdate the session past max age.
        auth._sessions[session_id] = (
            time.time() - auth.CONFIG_API_SESSION_MAX_AGE_SECONDS - 1
        )
        assert auth.validate_session(session_id) is False
        assert session_id not in auth._sessions

    def test_empty_string_returns_false(self) -> None:
        """An empty string session ID returns False."""
        assert auth.validate_session("") is False


# ---------------------------------------------------------------------------
# revoke_session
# ---------------------------------------------------------------------------


class TestRevokeSession:
    """Tests for revoke_session()."""

    def setup_method(self) -> None:
        """Reset module state before each test."""
        _reload_auth()

    def test_removes_existing_session(self) -> None:
        """Revoking an existing session removes it from the store."""
        session_id = auth.create_session()
        assert session_id in auth._sessions
        auth.revoke_session(session_id)
        assert session_id not in auth._sessions

    def test_noop_for_unknown_id(self) -> None:
        """Revoking an unknown session ID does not raise."""
        auth.revoke_session("nonexistent")
        # Should not raise.


# ---------------------------------------------------------------------------
# cleanup_expired_sessions
# ---------------------------------------------------------------------------


class TestCleanupExpiredSessions:
    """Tests for cleanup_expired_sessions()."""

    def setup_method(self) -> None:
        """Reset module state before each test."""
        _reload_auth()

    def test_removes_expired_sessions(self) -> None:
        """Expired sessions are removed from the store."""
        # Create a valid and an expired session.
        valid_id = auth.create_session()
        expired_id = auth.create_session()
        auth._sessions[expired_id] = (
            time.time() - auth.CONFIG_API_SESSION_MAX_AGE_SECONDS - 1
        )
        auth.cleanup_expired_sessions()
        assert valid_id in auth._sessions
        assert expired_id not in auth._sessions

    def test_keeps_valid_sessions(self) -> None:
        """Non-expired sessions remain in the store."""
        sid1 = auth.create_session()
        sid2 = auth.create_session()
        auth.cleanup_expired_sessions()
        assert sid1 in auth._sessions
        assert sid2 in auth._sessions

    def test_empty_store(self) -> None:
        """Cleanup on an empty store does not raise."""
        auth.cleanup_expired_sessions()

    def test_all_expired(self) -> None:
        """When all sessions are expired, the store is emptied."""
        sid1 = auth.create_session()
        sid2 = auth.create_session()
        auth._sessions[sid1] = 1.0  # very old
        auth._sessions[sid2] = 2.0  # very old
        auth.cleanup_expired_sessions()
        assert len(auth._sessions) == 0
