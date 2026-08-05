#!/usr/bin/env python3
"""
SSH MCP Server for Bifrost - Streamable HTTP transport.
"""
import argparse
import atexit
import json
import os
import sys
import re
from pathlib import Path

import paramiko
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Settings

from lib.config import ConfigManager, ConfigValidationError
from lib.health import attach_health_endpoint


def resolve_config_dir() -> str:
    """
    Resolve config directory from CLI args or environment.
    
    Priority: --config-dir CLI arg > CONFIG_DIR env var > /config (default)
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config-dir", type=str, default=None)
    args, _ = parser.parse_known_args()
    
    if args.config_dir:
        return args.config_dir
    return os.environ.get("CONFIG_DIR", "/config")


BASE_DIR = Path(__file__).parent

# Config directory resolution
CONFIG_DIR = resolve_config_dir()

# Initialize configuration manager with graceful fallback
try:
    config_manager = ConfigManager(CONFIG_DIR)
    # Start hot-reload watcher (15-second polling)
    config_manager.start_watcher(polling_interval=15.0)
except Exception:
    import logging
    _logger = logging.getLogger(__name__)
    _logger.warning(
        "Cannot initialize ConfigManager from %s — falling back to "
        "bundled default config (read-only, no hot-reload). "
        "Ensure the config directory is writable by the container user.",
        CONFIG_DIR,
        exc_info=True,
    )
    # Fallback: load bundled default-config.json via ConfigManager
    # pointed at /app (which is always writable by the mcpssh user).
    _fallback_config_dir = str(BASE_DIR)
    config_manager = ConfigManager(_fallback_config_dir)
    _logger.info(
        "Config loaded from fallback path: %s",
        config_manager.config_path,
    )

mcp = FastMCP(
    "ssh-mcp-server",
    instructions="Secure SSH command execution for Homelab. Use ssh_list_servers first, then ssh_execute_command.",
    host="0.0.0.0",
    port=8080,
    streamable_http_path="/mcp",
)

# Attach health check endpoint
attach_health_endpoint(mcp)

def check_block_patterns(command: str) -> bool:
    """
    Check if the command matches any block pattern.
    Returns True if command is BLOCKED, False if it passes.
    Reads patterns from live config (supports hot-reload).
    """
    patterns = config_manager.data.get("block_patterns", [])
    for pattern in patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


def is_command_allowed(server_name: str, command: str) -> bool:
    """
    Check if the command is allowed for the given server.
    Reads rules from live config (supports hot-reload).
    
    For now, only checks the 'default' section.
    API key and network rules will be handled in Plan 03.
    """
    allowed = config_manager.data.get("allowed_commands", {})
    default_rules = allowed.get("default", [])
    
    base_cmd = command.strip().split()[0] if command.strip() else ""
    
    for rule in default_rules:
        targets = rule.get("targets", [])
        commands = rule.get("commands", [])
        
        # Check if this rule applies to the given server
        target_match = "*" in targets or server_name in targets
        if not target_match:
            continue
        
        # Check if the command is allowed
        if "*" in commands or base_cmd in commands:
            return True
    
    return False


def validate_command(command: str) -> bool:
    """Validate a command against block patterns only."""
    if check_block_patterns(command):
        return False
    return True


def get_ssh_client(server_name: str):
    """
    Create and return an SSH client connected to the named server.
    Reads connection details from ConfigManager.
    """
    target = config_manager.get_ssh_target(server_name)
    if target is None:
        available = ", ".join(config_manager.list_ssh_targets())
        raise ValueError(f"Server '{server_name}' not found. Available: {available}")
    
    host = target["host"]
    port = target.get("port", 22)
    username = target["username"]
    
    # private_key takes precedence for SSH authentication
    key_path = target.get("private_key")
    password = target.get("password")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 10,
    }
    
    if key_path:
        key_path = os.path.expanduser(key_path)
        if os.path.exists(key_path):
            # Try Ed25519 first, then RSA
            key = None
            for key_class in (paramiko.Ed25519Key, paramiko.RSAKey):
                try:
                    key = key_class.from_private_key_file(key_path)
                    break
                except Exception:
                    continue
            if key:
                connect_kwargs["pkey"] = key
    elif password:
        connect_kwargs["password"] = password
    
    client.connect(**connect_kwargs)
    return client


@mcp.tool()
def ssh_list_servers() -> str:
    """
    List all available SSH target servers.
    Returns JSON with server IDs and their connection details (without secrets).
    """
    targets = config_manager.list_ssh_targets()
    result = {}
    for tid in targets:
        t = config_manager.get_ssh_target(tid)
        result[tid] = {
            "host": t["host"],
            "port": t.get("port", 22),
            "username": t["username"],
        }
    return json.dumps(result, indent=2)


@mcp.tool()
def ssh_execute_command(server_name: str, command: str, timeout: int = 30) -> str:
    """
    Execute a command on a remote SSH server.
    
    Args:
        server_name: Name of the server (from ssh_list_servers)
        command: Shell command to execute (whitelist-enforced)
        timeout: Command timeout in seconds (default 30, max 120)
    """
    if not is_command_allowed(server_name, command):
        return f"ERROR: Command '{command}' is not allowed."
    
    if not validate_command(command):
        return f"ERROR: Command '{command}' is blocked by security patterns."
    
    max_timeout = config_manager.data.get("settings", {}).get("command_timeout_max", 120)
    if timeout > max_timeout:
        timeout = max_timeout
    
    max_output = config_manager.data.get("settings", {}).get("max_output_length", 50000)
    
    try:
        client = get_ssh_client(server_name)
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read(max_output).decode('utf-8', errors='replace')
            err = stderr.read(max_output).decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            
            result = out
            if err:
                result += f"\n[STDERR]\n{err}"
            if exit_code != 0:
                result += f"\n[EXIT: {exit_code}]"
            if len(out) >= max_output:
                result += "\n[OUTPUT TRUNCATED]"
            return result
        finally:
            client.close()
    except Exception as e:
        return f"ERROR: {str(e)}"

@mcp.tool()
def ssh_download_file(server_name: str, remote_path: str) -> str:
    """
    Download a file from a remote server (returns content).
    """
    try:
        client = get_ssh_client(server_name)
        try:
            sftp = client.open_sftp()
            try:
                with sftp.file(remote_path, 'r') as f:
                    content = f.read(100000).decode('utf-8', errors='replace')
                return content
            finally:
                sftp.close()
        finally:
            client.close()
    except Exception as e:
        return f"ERROR: {str(e)}"

@mcp.tool()
def ssh_upload_file(server_name: str, remote_path: str, content: str, permissions: str = "0644") -> str:
    """
    Upload content to a remote server as a file.
    """
    if not (remote_path.startswith("/tmp/") or remote_path.startswith("/home/")):
        return "ERROR: Upload only allowed to /tmp/ or /home/ paths"
    
    try:
        client = get_ssh_client(server_name)
        try:
            sftp = client.open_sftp()
            try:
                with sftp.file(remote_path, 'w') as f:
                    f.write(content)
                sftp.chmod(remote_path, int(permissions, 8))
                return f"OK: Uploaded {len(content)} bytes to {remote_path}"
            finally:
                sftp.close()
        finally:
            client.close()
    except Exception as e:
        return f"ERROR: {str(e)}"

def shutdown():
    config_manager.stop_watcher()

atexit.register(shutdown)

if __name__ == "__main__":
    import asyncio
    asyncio.run(mcp.run_streamable_http_async())
