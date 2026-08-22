"""Unit tests for config_api.auth — Bearer token authentication.

Tests cover:
- load_token() reading from CONFIG_API_TOKEN env var
- load_token() raising RuntimeError when unset/empty
- get_token() returning the loaded token
- get_token() raising RuntimeError when not loaded
- verify_token() accepting valid tokens
- verify_token() rejecting invalid tokens with 401
- verify_token() rejecting missing Authorization header with 403
"""

from __future__ import annotations

import importlib
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from config_api import auth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reload_auth() -> None:
    """Reload the auth module to reset the module-level _token to None."""
    importlib.reload(auth)


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
# verify_token
# ---------------------------------------------------------------------------


class TestVerifyToken:
    """Tests for verify_token() dependency."""

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
        result = await auth.verify_token(credentials=creds)
        assert result == "correct-token"

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A token not matching the loaded token raises 401."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "correct-token")
        auth.load_token()
        creds = self._make_credentials("wrong-token")
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(credentials=creds)
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
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(credentials=creds)
        assert "super-secret-value" not in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_empty_provided_token_rejected(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty provided token is rejected."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "real-token")
        auth.load_token()
        creds = self._make_credentials("")
        with pytest.raises(HTTPException) as exc_info:
            await auth.verify_token(credentials=creds)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_timing_safe_comparison(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """verify_token uses hmac.compare_digest (timing-safe)."""
        monkeypatch.setenv("CONFIG_API_TOKEN", "token")
        auth.load_token()
        creds = self._make_credentials("token")
        with patch("config_api.auth.hmac") as mock_hmac:
            mock_hmac.compare_digest.return_value = True
            result = await auth.verify_token(credentials=creds)
            mock_hmac.compare_digest.assert_called_once_with("token", "token")
            assert result == "token"
