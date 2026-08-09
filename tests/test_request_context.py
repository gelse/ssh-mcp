"""Tests for lib.request_context — IP extraction middleware and API key extraction."""

from unittest.mock import MagicMock, patch

import pytest

from lib.request_context import (
    RequestContextMiddleware,
    get_api_key,
    get_client_ip,
    get_request_id,
)


def _make_mock_request(
    x_forwarded_for: str | None = None,
    client_host: str | None = None,
    x_api_key: str | None = None,
    authorization: str | None = None,
    x_request_id: str | None = None,
) -> MagicMock:
    """Build a mock Starlette Request with configurable headers and client."""
    request = MagicMock()
    headers: dict[str, str] = {}
    if x_forwarded_for is not None:
        headers["X-Forwarded-For"] = x_forwarded_for
    if x_api_key is not None:
        headers["X-API-Key"] = x_api_key
    if authorization is not None:
        headers["Authorization"] = authorization
    if x_request_id is not None:
        headers["X-Request-ID"] = x_request_id
    request.headers.get.side_effect = lambda key, default="": headers.get(key, default)

    if client_host is not None:
        request.client.host = client_host
    else:
        request.client = None

    return request


class TestExtractIp:
    """Tests for RequestContextMiddleware._extract_ip()."""

    # --- X-Forwarded-For scenarios ---------------------------------------

    def test_xff_single_ipv4(self):
        """Leftmost IPv4 in X-Forwarded-For is returned."""
        req = _make_mock_request(x_forwarded_for="10.0.0.55")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "10.0.0.55"

    def test_xff_multiple_ips_returns_leftmost(self):
        """When X-Forwarded-For has multiple proxies, the first (leftmost) is used."""
        req = _make_mock_request(x_forwarded_for="192.168.1.10, 10.0.0.1, 172.16.0.1")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "192.168.1.10"

    def test_xff_with_port_stripped(self):
        """IPv4 with port notation (e.g. '192.168.1.10:443') is treated as single IP."""
        req = _make_mock_request(x_forwarded_for="192.168.1.10:443")
        result = RequestContextMiddleware._extract_ip(req)
        # ipaddress.ip_address rejects port notations → falls back to 127.0.0.1
        assert result == "127.0.0.1"

    def test_xff_ipv6(self):
        """IPv6 address in X-Forwarded-For is returned."""
        req = _make_mock_request(x_forwarded_for="::1")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "::1"

    def test_xff_full_ipv6(self):
        """Full IPv6 address in X-Forwarded-For is returned."""
        req = _make_mock_request(x_forwarded_for="2001:db8::1")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "2001:db8::1"

    def test_xff_multiple_with_ipv6(self):
        """Multiple entries with IPv6 as original client."""
        req = _make_mock_request(
            x_forwarded_for="fe80::1, 10.0.0.1, 192.168.1.1"
        )
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "fe80::1"

    # --- Direct client IP fallback --------------------------------------

    def test_direct_client_ipv4(self):
        """Without X-Forwarded-For, request.client.host is used."""
        req = _make_mock_request(client_host="10.0.0.99")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "10.0.0.99"

    def test_direct_client_ipv6(self):
        """Direct IPv6 connection address is used."""
        req = _make_mock_request(client_host="::1")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "::1"

    # --- Invalid / missing IP fallback ----------------------------------

    def test_invalid_ip_returns_default(self):
        """Garbage in X-Forwarded-For falls back to 127.0.0.1."""
        req = _make_mock_request(x_forwarded_for="not-an-ip")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "127.0.0.1"

    def test_empty_xff_no_client_returns_default(self):
        """Empty X-Forwarded-For and no client falls back to 127.0.0.1."""
        req = _make_mock_request(x_forwarded_for="")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "127.0.0.1"

    def test_invalid_xff_with_valid_client(self):
        """Invalid X-Forwarded-For with valid client host falls back to 127.0.0.1."""
        req = _make_mock_request(
            x_forwarded_for="invalid!@#", client_host="192.168.1.50"
        )
        result = RequestContextMiddleware._extract_ip(req)
        # X-Forwarded-For is checked first, its value is invalid → fallback
        assert result == "127.0.0.1"

    def test_bogus_ipv4_range(self):
        """Out-of-range IPv4 octets (e.g. 999.999.999.999) fall back."""
        req = _make_mock_request(x_forwarded_for="999.999.999.999")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "127.0.0.1"


class TestGetClientIpDefault:
    """Tests for get_client_ip() when called outside request context."""

    def test_returns_default_outside_context(self):
        """get_client_ip() returns '127.0.0.1' when no middleware has run."""
        # No middleware has set the context var → default applies
        assert get_client_ip() == "127.0.0.1"


# ------------------------------------------------------------------
# API key extraction tests
# ------------------------------------------------------------------


class TestExtractApiKey:
    """Tests for RequestContextMiddleware._extract_api_key()."""

    # --- X-API-Key header ------------------------------------------------

    def test_x_api_key_header(self):
        """X-API-Key header returns the raw key."""
        req = _make_mock_request(x_api_key="my-secret-key")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == "my-secret-key"

    def test_x_api_key_empty_string_returns_none(self):
        """Empty X-API-Key header returns None."""
        req = _make_mock_request(x_api_key="")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    # --- Authorization: Bearer header ------------------------------------

    def test_authorization_bearer(self):
        """Authorization: Bearer <key> returns the key."""
        req = _make_mock_request(authorization="Bearer abc123")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == "abc123"

    def test_authorization_bearer_with_spaces_in_key(self):
        """Bearer key can contain internal spaces."""
        req = _make_mock_request(authorization="Bearer my key with spaces")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == "my key with spaces"

    def test_authorization_bearer_empty_key_returns_none(self):
        """Authorization: Bearer  (with no key) returns None."""
        req = _make_mock_request(authorization="Bearer ")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    def test_authorization_non_bearer_returns_none(self):
        """Authorization: Basic <creds> is ignored."""
        req = _make_mock_request(authorization="Basic dXNlcjpwYXNz")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    def test_authorization_bearer_case_sensitive_prefix(self):
        """Only exact 'Bearer ' prefix is recognised."""
        req = _make_mock_request(authorization="bearer abc123")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    # --- Priority: X-API-Key over Authorization --------------------------

    def test_x_api_key_takes_priority_over_bearer(self):
        """When both headers are present, X-API-Key wins."""
        req = _make_mock_request(
            x_api_key="from-x-api-key",
            authorization="Bearer from-bearer",
        )
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == "from-x-api-key"

    # --- No header scenarios ---------------------------------------------

    def test_no_headers_returns_none(self):
        """No relevant headers → None."""
        req = _make_mock_request()
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    def test_only_x_forwarded_for_returns_none(self):
        """Only X-Forwarded-For header → None for API key."""
        req = _make_mock_request(x_forwarded_for="10.0.0.1")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    # --- Length validation -----------------------------------------------

    def test_key_at_max_length(self):
        """A key at exactly the max allowed length is accepted."""
        key = "a" * 512
        req = _make_mock_request(x_api_key=key)
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == key

    def test_key_exceeds_max_length_returns_none(self):
        """A key longer than the max allowed length is rejected."""
        key = "a" * 513
        req = _make_mock_request(x_api_key=key)
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    def test_bearer_key_exceeds_max_length_returns_none(self):
        """Bearer key exceeding max length is rejected."""
        key = "b" * 513
        req = _make_mock_request(authorization=f"Bearer {key}")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None


class TestGetApiKeyDefault:
    """Tests for get_api_key() when called outside request context."""

    def test_returns_none_outside_context(self):
        """get_api_key() returns None when no middleware has run."""
        assert get_api_key() is None


class TestExtractRequestId:
    """Tests for RequestContextMiddleware._extract_request_id()."""

    def test_header_present_is_returned(self):
        """A non-empty X-Request-ID header is returned unchanged."""
        req = _make_mock_request(x_request_id="req-abc-123")
        result = RequestContextMiddleware._extract_request_id(req)
        assert result == "req-abc-123"

    def test_missing_header_returns_none(self):
        """No X-Request-ID header yields None."""
        req = _make_mock_request()
        result = RequestContextMiddleware._extract_request_id(req)
        assert result is None

    def test_empty_header_returns_none(self):
        """An empty X-Request-ID header yields None."""
        req = _make_mock_request(x_request_id="")
        result = RequestContextMiddleware._extract_request_id(req)
        assert result is None

    def test_whitespace_is_stripped(self):
        """Surrounding whitespace is stripped from the header value."""
        req = _make_mock_request(x_request_id="  req-abc-123  ")
        result = RequestContextMiddleware._extract_request_id(req)
        assert result == "req-abc-123"

    def test_whitespace_only_returns_none(self):
        """A whitespace-only header is treated as missing."""
        req = _make_mock_request(x_request_id="   ")
        result = RequestContextMiddleware._extract_request_id(req)
        assert result is None

    def test_overlong_header_is_truncated(self):
        """Header values longer than the max length are truncated."""
        long_id = "x" * 200
        req = _make_mock_request(x_request_id=long_id)
        result = RequestContextMiddleware._extract_request_id(req)
        assert result is not None
        assert len(result) == 128
        assert result == long_id[:128]


class TestGetRequestIdDefault:
    """Tests for get_request_id() when called outside request context."""

    def test_returns_unknown_outside_context(self):
        """The constant ``"unknown"`` is returned outside request context."""
        with patch("lib.request_context._get_mcp_request", return_value=None):
            request_id = get_request_id()
        assert request_id == "unknown"

    def test_unknown_is_cached_within_request(self):
        """Repeated calls outside a request consistently return ``"unknown"``."""
        with patch("lib.request_context._get_mcp_request", return_value=None):
            first = get_request_id()
            second = get_request_id()
        assert first == second == "unknown"
