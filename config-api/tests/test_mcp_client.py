"""Tests for config_api.mcp_client — lightweight JSON-RPC 2.0 client for MCP tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from config_api.mcp_client import MCPClient, MCPClientError, MCPToolError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jsonrpc_response(text: str, request_id: int = 1) -> dict:
    """Build a minimal JSON-RPC 2.0 success response wrapping MCP tool output."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": text}],
        },
    }


def _make_jsonrpc_error(
    message: str, code: int = -32603, request_id: int = 1
) -> dict:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _make_init_response(session_id: str = "test-session-123") -> MagicMock:
    """Build a mock response for the ``initialize`` handshake."""
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.headers = {"mcp-session-id": session_id}
    resp.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "serverInfo": {"name": "mcp-ssh", "version": "1.0.0"},
        },
    }
    return resp


def _make_notification_response() -> MagicMock:
    """Build a mock response for a JSON-RPC notification (202 Accepted)."""
    resp = MagicMock()
    resp.status_code = 202
    resp.raise_for_status = MagicMock()
    return resp


def _make_tool_response(payload: dict, request_id: int = 3) -> MagicMock:
    """Build a mock response for a ``tools/call`` request."""
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = _make_jsonrpc_response(json.dumps(payload), request_id)
    return resp


def _make_init_side_effect(session_id: str = "test-session-123"):
    """Return a side_effect callable for httpx.Client.post that handles the
    full session lifecycle: initialize → notification → tool call."""
    init_resp = _make_init_response(session_id)
    notif_resp = _make_notification_response()

    def _side_effect(*args, **kwargs):
        method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
        if method == "initialize":
            return init_resp
        elif method == "notifications/initialized":
            return notif_resp
        else:
            # Tool call — return a default; callers can override via side_effect
            return _make_tool_response({"success": True, "output": "ok"})

    return _side_effect


def _make_mock_http(side_effect=None):
    """Build a mock httpx.Client with the given post side_effect."""
    mock_instance = MagicMock()
    if side_effect:
        mock_instance.post.side_effect = side_effect
    mock_instance.__enter__ = MagicMock(return_value=mock_instance)
    mock_instance.__exit__ = MagicMock(return_value=False)
    return mock_instance


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMCPClient:
    """Tests for MCPClient.call_tool()."""

    def test_call_tool_success(self) -> None:
        """Successful tool call returns parsed JSON from the MCP response."""
        tool_result = {
            "success": True,
            "output": "pong",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }

        side_effect = _make_init_side_effect()
        mock_http = _make_mock_http(side_effect)

        # Override the tool-call response
        tool_resp = _make_tool_response(tool_result, request_id=3)
        original_side_effect = side_effect

        def _patched_side_effect(*args, **kwargs):
            method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
            if method in ("initialize", "notifications/initialized"):
                return original_side_effect(*args, **kwargs)
            return tool_resp

        mock_http.post.side_effect = _patched_side_effect

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            result = client.call_tool(
                "ssh_check_connection",
                arguments={"server_name": "test-server", "timeout": 10},
            )

        assert result == tool_result
        # 3 calls: initialize, notifications/initialized, tools/call
        assert mock_http.post.call_count == 3

        # Verify the tool-call payload
        tool_call = mock_http.post.call_args_list[2]
        payload = tool_call[1]["json"]
        assert payload["jsonrpc"] == "2.0"
        assert payload["method"] == "tools/call"
        assert payload["params"]["name"] == "ssh_check_connection"
        assert payload["params"]["arguments"]["server_name"] == "test-server"

        # Verify session id was captured and sent
        tool_call_headers = tool_call[1]["headers"]
        assert "mcp-session-id" in tool_call_headers

    def test_call_tool_json_rpc_error(self) -> None:
        """JSON-RPC error response raises MCPToolError."""
        error_resp = _make_tool_response(
            {"success": False}, request_id=3
        )
        error_resp.json.return_value = _make_jsonrpc_error(
            "Server 'unknown' not found", request_id=3
        )

        side_effect = _make_init_side_effect()

        def _patched_side_effect(*args, **kwargs):
            method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
            if method in ("initialize", "notifications/initialized"):
                return side_effect(*args, **kwargs)
            return error_resp

        mock_http = _make_mock_http(_patched_side_effect)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            with pytest.raises(MCPToolError, match="Server 'unknown' not found"):
                client.call_tool("ssh_check_connection", arguments={"server_name": "unknown"})

    def test_call_tool_http_error_during_init(self) -> None:
        """HTTP error during initialize raises MCPClientError."""
        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.text = "Internal Server Error"
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=error_resp,
        )

        mock_http = _make_mock_http(lambda *a, **kw: error_resp)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            with pytest.raises(MCPClientError, match="initialize failed.*HTTP 500"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_http_error_during_tool_call(self) -> None:
        """HTTP error during tools/call raises MCPClientError."""
        side_effect = _make_init_side_effect()

        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.text = "Internal Server Error"
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=error_resp,
        )

        def _patched_side_effect(*args, **kwargs):
            method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
            if method in ("initialize", "notifications/initialized"):
                return side_effect(*args, **kwargs)
            return error_resp

        mock_http = _make_mock_http(_patched_side_effect)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            with pytest.raises(MCPClientError, match="HTTP 500"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_connection_error(self) -> None:
        """Connection error raises MCPClientError."""
        error_resp = MagicMock()
        error_resp.raise_for_status.side_effect = httpx.ConnectError(
            "Connection refused"
        )

        mock_http = _make_mock_http(lambda *a, **kw: error_resp)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            with pytest.raises(MCPClientError, match="Failed to connect"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_invalid_json_during_init(self) -> None:
        """Non-JSON response during initialize raises MCPClientError."""
        bad_resp = MagicMock()
        bad_resp.status_code = 200
        bad_resp.raise_for_status = MagicMock()
        bad_resp.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        bad_resp.text = "not json"

        mock_http = _make_mock_http(lambda *a, **kw: bad_resp)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            with pytest.raises(MCPClientError, match="Invalid JSON in initialize"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_empty_result(self) -> None:
        """Empty content array raises MCPClientError."""
        empty_resp = MagicMock()
        empty_resp.status_code = 200
        empty_resp.raise_for_status = MagicMock()
        empty_resp.json.return_value = {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"content": []},
        }

        side_effect = _make_init_side_effect()

        def _patched_side_effect(*args, **kwargs):
            method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
            if method in ("initialize", "notifications/initialized"):
                return side_effect(*args, **kwargs)
            return empty_resp

        mock_http = _make_mock_http(_patched_side_effect)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            with pytest.raises(MCPClientError, match="empty result"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_non_json_text(self) -> None:
        """Non-JSON text in content[0].text returns fallback dict."""
        text_resp = MagicMock()
        text_resp.status_code = 200
        text_resp.raise_for_status = MagicMock()
        text_resp.json.return_value = {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "content": [{"type": "text", "text": "plain text output"}],
            },
        }

        side_effect = _make_init_side_effect()

        def _patched_side_effect(*args, **kwargs):
            method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
            if method in ("initialize", "notifications/initialized"):
                return side_effect(*args, **kwargs)
            return text_resp

        mock_http = _make_mock_http(_patched_side_effect)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            result = client.call_tool("ssh_check_connection")

        assert result == {"output": "plain text output", "success": True}

    def test_request_id_increments(self) -> None:
        """Each call increments the JSON-RPC request id."""
        tool_result = '{"ok": true}'

        side_effect = _make_init_side_effect()

        def _patched_side_effect(*args, **kwargs):
            method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
            if method in ("initialize", "notifications/initialized"):
                return side_effect(*args, **kwargs)
            return _make_tool_response(tool_result, request_id=kwargs.get("json", {}).get("id", 3))

        mock_http = _make_mock_http(_patched_side_effect)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            # First call triggers init (id=1) + notif (no id) + tool call (id=2)
            client.call_tool("ssh_check_connection")
            # Second call is just tool call (id=3)
            client.call_tool("ssh_check_connection")
            # Third call is just tool call (id=4)
            client.call_tool("ssh_check_connection")

        calls = mock_http.post.call_args_list
        # Notifications (e.g. notifications/initialized) carry no id per
        # JSON-RPC 2.0, so they do not consume the request-id counter.
        # ids: 1 (init), [nothing: notif], 2 (tool1), 3 (tool2), 4 (tool3)
        assert "id" not in calls[1][1]["json"]  # notification has no id
        assert calls[0][1]["json"]["id"] == 1  # initialize
        assert calls[2][1]["json"]["id"] == 2  # first tool call
        assert calls[3][1]["json"]["id"] == 3  # second tool call
        assert calls[4][1]["json"]["id"] == 4  # third tool call

    def test_session_id_sent_on_tool_call(self) -> None:
        """The mcp-session-id header is included on tool call requests."""
        session_id = "my-session-abc"
        side_effect = _make_init_side_effect(session_id=session_id)

        def _patched_side_effect(*args, **kwargs):
            method = kwargs.get("json", {}).get("method", "") if kwargs.get("json") else ""
            if method in ("initialize", "notifications/initialized"):
                return side_effect(*args, **kwargs)
            return _make_tool_response({"success": True}, request_id=3)

        mock_http = _make_mock_http(_patched_side_effect)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            MockHTTP.return_value = mock_http

            client.call_tool("ssh_check_connection")

        # The tool call (3rd request) should include the session id
        tool_call = mock_http.post.call_args_list[2]
        headers = tool_call[1]["headers"]
        assert headers["mcp-session-id"] == session_id

    def test_default_url_from_env(self) -> None:
        """MCPClient falls back to MCP_SERVER_URL env var."""
        with patch.dict("os.environ", {"MCP_SERVER_URL": "http://custom:9090/mcp"}):
            client = MCPClient()
            assert client._base_url == "http://custom:9090/mcp"

    def test_default_url_constant(self) -> None:
        """MCPClient uses DEFAULT_MCP_SERVER_URL when no env var is set."""
        with patch.dict("os.environ", {}, clear=True):
            client = MCPClient()
            assert client._base_url == "http://mcp-ssh:8080/mcp"

    def test_explicit_url_overrides_env(self) -> None:
        """Explicit base_url parameter takes precedence over env var."""
        with patch.dict("os.environ", {"MCP_SERVER_URL": "http://env:9090/mcp"}):
            client = MCPClient(base_url="http://explicit:7070/mcp")
            assert client._base_url == "http://explicit:7070/mcp"
