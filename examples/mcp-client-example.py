"""Programmatic MCP client example for the mcp-ssh server.

Demonstrates how to call all six mcp-ssh tools with the `fastmcp`
client library over the Streamable HTTP transport:

    1. ssh_list_servers
    2. ssh_list_allowed_commands
    3. ssh_execute_command
    4. ssh_check_connection
    5. ssh_download_file
    6. ssh_upload_file

Requirements:

    pip install fastmcp

Environment variables:

    MCP_SSH_URL      MCP endpoint (default: http://localhost:9080/mcp;
                     the Docker image listens on 8080, compose maps it
                     to host port 9080)
    MCP_SSH_API_KEY  API key sent as the X-API-Key header (required)
    MCP_SSH_SERVER   SSH target id to operate on (default: web-server)

Usage:

    export MCP_SSH_API_KEY="your-api-key"
    python mcp-client-example.py
"""

from __future__ import annotations

import asyncio
import os
import sys

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

MCP_URL = os.environ.get("MCP_SSH_URL", "http://localhost:9080/mcp")
API_KEY = os.environ.get("MCP_SSH_API_KEY", "")
SERVER_NAME = os.environ.get("MCP_SSH_SERVER", "web-server")


def _print_result(tool: str, result: object) -> None:
    """Print a tool result's text content to stdout.

    Args:
        tool: Name of the tool that produced the result (for logging).
        result: The ``CallToolResult`` returned by ``client.call_tool``.
    """
    print(f"--- {tool} ---")
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if text is not None:
            print(text)
    print()


async def main() -> None:
    """Run all six mcp-ssh tools against the configured server.

    Raises:
        SystemExit: If ``MCP_SSH_API_KEY`` is not set.
    """
    if not API_KEY:
        print(
            "ERROR: set MCP_SSH_API_KEY (the raw API key configured for "
            "your client)",
            file=sys.stderr,
        )
        raise SystemExit(1)

    transport = StreamableHttpTransport(
        url=MCP_URL,
        headers={"X-API-Key": API_KEY},
    )

    async with Client(transport) as client:
        print(f"Connected to {MCP_URL}")

        tools = await client.list_tools()
        print(f"Server exposes {len(tools)} tools:")
        for tool in tools:
            print(f"  - {tool.name}")
        print()

        # 1. List configured SSH targets (no secrets are returned).
        result = await client.call_tool("ssh_list_servers", {})
        _print_result("ssh_list_servers", result)

        # 2. List commands this client may run on the target
        #    (union of default + api_key + network rules).
        result = await client.call_tool(
            "ssh_list_allowed_commands", {"server_name": SERVER_NAME}
        )
        _print_result("ssh_list_allowed_commands", result)

        # 3. Execute a command over SSH.
        result = await client.call_tool(
            "ssh_execute_command",
            {"server_name": SERVER_NAME, "command": "uptime"},
        )
        _print_result("ssh_execute_command", result)

        # 3b. The same tool with the sudo flag. Sudo is only permitted
        #     for commands listed in a matching rule's "sudo_allowed";
        #     otherwise the server denies the call (ToolError).
        try:
            result = await client.call_tool(
                "ssh_execute_command",
                {
                    "server_name": SERVER_NAME,
                    "command": "systemctl status ssh",
                    "sudo": True,
                },
            )
        except ToolError as exc:
            print("--- ssh_execute_command (sudo=True) ---")
            print(f"denied: {exc}")
            print()
        else:
            _print_result("ssh_execute_command (sudo=True)", result)

        # 4. Check SSH connectivity (runs the target's "checkcommand").
        result = await client.call_tool(
            "ssh_check_connection", {"server_name": SERVER_NAME}
        )
        _print_result("ssh_check_connection", result)

        # 5. Download a file via SFTP (authorized like `cat <path>`).
        result = await client.call_tool(
            "ssh_download_file",
            {"server_name": SERVER_NAME, "remote_path": "/etc/hostname"},
        )
        _print_result("ssh_download_file", result)

        # 6. Upload a file via SFTP (authorized like `tee <path>`).
        #    Remote paths must start with /tmp/ or /home/.
        result = await client.call_tool(
            "ssh_upload_file",
            {
                "server_name": SERVER_NAME,
                "remote_path": "/tmp/hello-mcp-ssh.txt",
                "content": "Hello from mcp-ssh!",
                "permissions": "0644",
            },
        )
        _print_result("ssh_upload_file", result)


if __name__ == "__main__":
    asyncio.run(main())
