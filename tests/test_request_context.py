"""Tests for lib.request_context — IP extraction middleware and API key extraction."""

from unittest.mock import MagicMock, patch

import pytest

from lib.constants import DEFAULT_REQUEST_ID, FALLBACK_CLIENT_IP
from lib.request_context import (
    RequestContextMiddleware,
    get_api_key,
    get_client_ip,
    get_current_request,
    get_request_id,
)


# A direct connection peer trusted to supply X-Forwarded-For. Used by the
# XFF tests below so the header is actually honored under the new
# trusted-proxy gating.
_TRUSTED_PROXY = "203.0.113.10"


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

    # --- X-Forwarded-For scenarios (trusted proxy) -----------------------

    def test_xff_single_ipv4(self):
        """Leftmost IPv4 in X-Forwarded-For is returned from a trusted proxy."""
        req = _make_mock_request(
            x_forwarded_for="10.0.0.55", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "10.0.0.55"

    def test_xff_multiple_ips_returns_leftmost(self):
        """When X-Forwarded-For has multiple proxies, the first (leftmost) is used."""
        req = _make_mock_request(
            x_forwarded_for="192.168.1.10, 10.0.0.1, 172.16.0.1",
            client_host=_TRUSTED_PROXY,
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "192.168.1.10"

    def test_xff_with_port_stripped(self):
        """IPv4 with port notation (e.g. '192.168.1.10:443') is treated as single IP."""
        req = _make_mock_request(
            x_forwarded_for="192.168.1.10:443", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        # ipaddress.ip_address rejects port notations → falls back to FALLBACK_CLIENT_IP
        assert result == FALLBACK_CLIENT_IP

    def test_xff_ipv6(self):
        """IPv6 address in X-Forwarded-For is returned."""
        req = _make_mock_request(
            x_forwarded_for="::1", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "::1"

    def test_xff_full_ipv6(self):
        """Full IPv6 address in X-Forwarded-For is returned."""
        req = _make_mock_request(
            x_forwarded_for="2001:db8::1", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "2001:db8::1"

    def test_xff_multiple_with_ipv6(self):
        """Multiple entries with IPv6 as original client."""
        req = _make_mock_request(
            x_forwarded_for="fe80::1, 10.0.0.1, 192.168.1.1",
            client_host=_TRUSTED_PROXY,
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "fe80::1"

    # --- X-Forwarded-For trust / spoofing gating -------------------------

    def test_xff_ignored_when_no_trusted_proxy_configured(self):
        """With an empty trusted-proxy list, X-Forwarded-For is never honored."""
        req = _make_mock_request(
            x_forwarded_for="10.0.0.55", client_host="203.0.113.99"
        )
        # trusted_proxies defaults to [] → header ignored → direct IP used
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "203.0.113.99"

    def test_xff_ignored_when_direct_peer_not_trusted(self):
        """Spoofed X-Forwarded-For is ignored when the peer is not trusted."""
        req = _make_mock_request(
            x_forwarded_for="10.0.0.55", client_host="198.51.100.7"
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        # peer not in trusted list → header ignored → direct IP used
        assert result == "198.51.100.7"

    def test_xff_ignored_when_no_client_host(self):
        """No direct peer means X-Forwarded-For cannot be trusted."""
        req = _make_mock_request(x_forwarded_for="10.0.0.55")
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == FALLBACK_CLIENT_IP

    def test_trusted_proxy_ipv4_mapped_to_ipv4(self):
        """IPv4-mapped IPv6 trusted proxy is normalized to IPv4 and honored."""
        req = _make_mock_request(
            x_forwarded_for="10.0.0.55", client_host="::ffff:203.0.113.10"
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "10.0.0.55"

    # --- IPv4-mapped IPv6 normalization ---------------------------------

    def test_xff_ipv4_mapped_ipv6_normalized_to_ipv4(self):
        """IPv4-mapped IPv6 in X-Forwarded-For collapses to IPv4."""
        req = _make_mock_request(
            x_forwarded_for="::ffff:192.168.1.10", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "192.168.1.10"

    def test_direct_client_ipv4_mapped_ipv6_normalized_to_ipv4(self):
        """IPv4-mapped IPv6 direct peer is normalized to IPv4."""
        req = _make_mock_request(client_host="::ffff:10.0.0.99")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "10.0.0.99"

    def test_plain_ipv6_not_normalized(self):
        """A real (non-mapped) IPv6 address is preserved as-is."""
        req = _make_mock_request(client_host="2001:db8::1234")
        result = RequestContextMiddleware._extract_ip(req)
        assert result == "2001:db8::1234"

    # --- Malformed X-Forwarded-For ---------------------------------------

    def test_xff_leading_trailing_whitespace_trimmed(self):
        """Whitespace around the leftmost X-Forwarded-For entry is trimmed."""
        req = _make_mock_request(
            x_forwarded_for="  10.0.0.55  , 203.0.113.10", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == "10.0.0.55"

    def test_xff_empty_first_entry_falls_back(self):
        """An empty leftmost X-Forwarded-For entry is not a valid IP."""
        req = _make_mock_request(
            x_forwarded_for=", 10.0.0.1", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == FALLBACK_CLIENT_IP

    def test_xff_extra_text_after_ip_rejected(self):
        """An X-Forwarded-For entry with trailing text is rejected as invalid."""
        req = _make_mock_request(
            x_forwarded_for="10.0.0.55:8080, 203.0.113.10", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == FALLBACK_CLIENT_IP

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
        """Garbage in X-Forwarded-For falls back to FALLBACK_CLIENT_IP."""
        req = _make_mock_request(
            x_forwarded_for="not-an-ip", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == FALLBACK_CLIENT_IP

    def test_empty_xff_with_client_returns_direct_ip(self):
        """Empty X-Forwarded-For with a present client returns the direct IP."""
        req = _make_mock_request(
            x_forwarded_for="", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        assert result == _TRUSTED_PROXY

    def test_invalid_xff_with_valid_client(self):
        """Invalid X-Forwarded-For with valid client host can fall back to direct IP."""
        req = _make_mock_request(
            x_forwarded_for="invalid!@#", client_host="192.168.1.50"
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        # header is untrusted (peer not in list) and invalid → direct IP used
        assert result == "192.168.1.50"

    def test_bogus_ipv4_range(self):
        """Out-of-range IPv4 octets (e.g. 999.999.999.999) fall back."""
        req = _make_mock_request(
            x_forwarded_for="999.999.999.999", client_host=_TRUSTED_PROXY
        )
        result = RequestContextMiddleware._extract_ip(
            req, trusted_proxies=[_TRUSTED_PROXY]
        )
        # peer is trusted, but the XFF value is not a valid IP → fallback
        assert result == FALLBACK_CLIENT_IP

    def test_no_client_no_xff_returns_default(self):
        """No X-Forwarded-For and no client falls back to FALLBACK_CLIENT_IP."""
        req = _make_mock_request()
        result = RequestContextMiddleware._extract_ip(req)
        assert result == FALLBACK_CLIENT_IP


class TestGetClientIp:
    """Tests for get_client_ip() resolving the client IP."""

    def _make_mcp_request(
        self,
        x_forwarded_for: str | None,
        client_host: str | None,
        trusted_proxies: list[str] | None,
    ) -> MagicMock:
        """Build a mock per-message MCP Request with scope-state trusted proxies."""
        request = _make_mock_request(
            x_forwarded_for=x_forwarded_for, client_host=client_host
        )
        state: dict[str, object] = {}
        if trusted_proxies is not None:
            state["mcp_ssh_trusted_proxies"] = trusted_proxies
        request.scope = {"state": state}
        return request

    def test_honors_xff_when_direct_peer_in_trusted_scope_state(self):
        """Per-message path honors XFF when trusted_proxies are in scope state."""
        req = self._make_mcp_request(
            x_forwarded_for="10.1.2.3",
            client_host="203.0.113.10",
            trusted_proxies=["203.0.113.10"],
        )
        with patch("lib.request_context._get_mcp_request", return_value=req):
            assert get_client_ip() == "10.1.2.3"

    def test_ignores_xff_when_direct_peer_not_in_trusted_scope_state(self):
        """Per-message path falls back to the direct peer when untrusted."""
        req = self._make_mcp_request(
            x_forwarded_for="10.1.2.3",
            client_host="198.51.100.7",
            trusted_proxies=["203.0.113.10"],
        )
        with patch("lib.request_context._get_mcp_request", return_value=req):
            assert get_client_ip() == "198.51.100.7"

    def test_ignores_xff_when_no_trusted_proxies_in_scope_state(self):
        """Per-message path ignores XFF when scope state has no trusted proxies."""
        req = self._make_mcp_request(
            x_forwarded_for="10.1.2.3",
            client_host="203.0.113.10",
            trusted_proxies=None,
        )
        with patch("lib.request_context._get_mcp_request", return_value=req):
            assert get_client_ip() == "203.0.113.10"

    def test_returns_default_outside_context(self):
        """get_client_ip() returns FALLBACK_CLIENT_IP when no middleware has run."""
        # No middleware has set the context var → default applies
        assert get_client_ip() == FALLBACK_CLIENT_IP


class TestTrustedProxiesProvider:
    """Tests for the hot-reload-aware provider in RequestContextMiddleware."""

    def test_provider_is_used_when_set(self):
        """The live provider result overrides the static snapshot."""
        mw = RequestContextMiddleware(
            app=MagicMock(),
            trusted_proxies=["203.0.113.10"],
            trusted_proxies_provider=lambda: ["198.51.100.7"],
        )
        assert mw._current_trusted_proxies() == ["198.51.100.7"]

    def test_provider_updates_are_reflected(self):
        """A hot-reloaded provider value is picked up on each call."""
        current = ["198.51.100.7"]
        mw = RequestContextMiddleware(
            app=MagicMock(),
            trusted_proxies=["203.0.113.10"],
            trusted_proxies_provider=lambda: current,
        )
        assert mw._current_trusted_proxies() == ["198.51.100.7"]
        # Simulate a config hot-reload updating the trusted-proxy list.
        current = ["192.0.2.55"]
        assert mw._current_trusted_proxies() == ["192.0.2.55"]

    def test_static_snapshot_used_when_no_provider(self):
        """Without a provider the static snapshot captured at init is used."""
        mw = RequestContextMiddleware(
            app=MagicMock(), trusted_proxies=["203.0.113.10"]
        )
        assert mw._current_trusted_proxies() == ["203.0.113.10"]

    def test_defaults_to_empty_when_nothing_provided(self):
        """No trusted proxies configured → empty list (security-first)."""
        mw = RequestContextMiddleware(app=MagicMock())
        assert mw._current_trusted_proxies() == []


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
        """A key at exactly the max allowed length (1024) is accepted."""
        key = "a" * 1024
        req = _make_mock_request(x_api_key=key)
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == key

    def test_key_exactly_1024_accepted(self):
        """A key of exactly 1024 printable-ASCII chars is accepted."""
        key = "x" * 1024
        req = _make_mock_request(x_api_key=key)
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == key

    def test_key_exceeds_max_length_returns_none(self):
        """A key longer than the max allowed length (1025) is rejected."""
        key = "a" * 1025
        req = _make_mock_request(x_api_key=key)
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    def test_bearer_key_exceeds_max_length_returns_none(self):
        """Bearer key exceeding max length (1025) is rejected."""
        key = "b" * 1025
        req = _make_mock_request(authorization=f"Bearer {key}")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    # --- Printable-ASCII validation --------------------------------------

    def test_key_with_non_ascii_rejected(self):
        """A key containing non-ASCII Unicode chars (café) is rejected."""
        req = _make_mock_request(x_api_key="café")
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    def test_key_with_control_chars_rejected(self):
        """A key containing a control char (\\x1f) is rejected."""
        key = "abc\x1fdef"
        req = _make_mock_request(x_api_key=key)
        result = RequestContextMiddleware._extract_api_key(req)
        assert result is None

    def test_key_with_space_accepted(self):
        """A key containing a literal space (\\x20) is accepted."""
        key = "my key with spaces"
        req = _make_mock_request(x_api_key=key)
        result = RequestContextMiddleware._extract_api_key(req)
        assert result == key


class TestGetApiKeyDefault:
    """Tests for get_api_key() when called outside request context."""

    def test_returns_none_outside_context(self):
        """get_api_key() returns None when no middleware has run."""
        assert get_api_key() is None


class TestGetCurrentRequestDefault:
    """Tests for get_current_request() when called outside request context."""

    def test_returns_none_outside_context(self):
        """get_current_request() returns None when no middleware has run."""
        assert get_current_request() is None


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
        """DEFAULT_REQUEST_ID is returned outside request context."""
        with patch("lib.request_context._get_mcp_request", return_value=None):
            request_id = get_request_id()
        assert request_id == DEFAULT_REQUEST_ID

    def test_unknown_is_cached_within_request(self):
        """Repeated calls outside a request consistently return DEFAULT_REQUEST_ID."""
        with patch("lib.request_context._get_mcp_request", return_value=None):
            first = get_request_id()
            second = get_request_id()
        assert first == second == DEFAULT_REQUEST_ID
