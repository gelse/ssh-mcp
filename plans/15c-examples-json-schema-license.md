# 15c - Create Examples Directory, JSON Schema & Add License

**Parent Plan**: [15-documentation-inline-comments.md](plans/15-documentation-inline-comments.md)

## Objective
Create an `examples/` directory with sample client configurations and requests, create a JSON Schema file for config validation, and add a LICENSE file.

## Implementation Steps

### 1. Create `examples/` Directory Structure

```
examples/
├── README.md                  # Overview of all examples
├── claude-desktop-config.json # Claude Desktop MCP client config
├── config-basic.json          # Minimal config: one target, basic commands
├── config-multi-target.json   # Multiple targets with different auth
├── config-sudo.json           # Targets with sudo_allowed enabled
├── config-network-auth.json   # Network-based authorization rules
├── curl-examples.sh           # Curl commands for direct MCP protocol calls
└── mcp-client-example.py      # Python MCP client using fastmcp client library
```

### 2. `examples/README.md`
```markdown
# MCP-SSH Usage Examples

This directory contains example configurations and client code for the
mcp-ssh MCP server.

## Config Examples
- `config-basic.json` — Single SSH target with key auth, default allowlist
- `config-multi-target.json` — Multiple targets with different auth methods
- `config-sudo.json` — Targets with sudo_allowed enabled for privileged commands
- `config-network-auth.json` — Network-based command authorization

## Client Examples
- `claude-desktop-config.json` — Claude Desktop app MCP server configuration
- `curl-examples.sh` — Direct HTTP requests to the MCP JSON-RPC endpoint
- `mcp-client-example.py` — Python client using the fastmcp library

## Quick Test
```bash
# List available servers
curl -X POST https://localhost/mcp-ssh \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssh_list_servers"}}'
```
```

### 3. `examples/claude-desktop-config.json`
```json
{
  "mcpServers": {
    "mcp-ssh": {
      "url": "https://your-mcp-ssh-host/mcp-ssh",
      "headers": {
        "X-API-Key": "your-api-key-here"
      }
    }
  }
}
```

### 4. `examples/config-basic.json`
A minimal working config with one target:
```json
{
  "version": 1,
  "ssh_targets": [
    {
      "name": "web-server",
      "host": "192.168.1.10",
      "username": "deploy",
      "port": 22,
      "auth": {
        "type": "key",
        "key_filename": "/home/deploy/.ssh/id_ed25519"
      },
      "sudo_allowed": false
    }
  ],
  "block_patterns": [
    "rm\\s+-rf\\s+/",
    "shutdown",
    "reboot",
    "mkfs\\.",
    "dd\\s+if="
  ],
  "allowed_commands": {
    "default": ["uptime", "df", "free", "ps", "ls", "cat", "tail", "systemctl", "docker"]
  },
  "api_keys": {},
  "settings": {
    "max_command_output": "50kb",
    "command_timeout_seconds": 120,
    "log_file": "ssh-executions.log",
    "max_log_file_size_mb": 10,
    "max_log_backup_count": 5,
    "watcher_interval_seconds": 15
  }
}
```

### 5. `examples/config-multi-target.json`
Two targets, one with key auth, one with password auth, with API key rules:
```json
{
  "version": 1,
  "ssh_targets": [
    {
      "name": "web-prod",
      "host": "10.0.1.10",
      "username": "deploy",
      "port": 22,
      "auth": { "type": "key", "key_filename": "/home/deploy/.ssh/id_ed25519" },
      "sudo_allowed": false
    },
    {
      "name": "db-prod",
      "host": "10.0.1.20",
      "username": "admin",
      "port": 22,
      "auth": { "type": "password", "password": "change-me-in-secrets" },
      "sudo_allowed": true
    }
  ],
  "block_patterns": ["rm\\s+-rf\\s+/", "shutdown", "reboot", "mkfs\\.", "dd\\s+if="],
  "allowed_commands": {
    "default": ["uptime", "df", "free", "ps", "ls", "cat", "tail", "systemctl", "docker"],
    "api_keys": {
      "admin-key": {
        "commands": ["uptime", "df", "free", "ps", "ls", "cat", "tail", "systemctl", "docker", "journalctl", "netstat", "ss"],
        "description": "Full read-only access for monitoring service"
      }
    },
    "networks": {
      "10.0.0.0/8": {
        "commands": ["uptime", "df", "free", "ps"],
        "description": "Basic health checks from internal network"
      }
    }
  },
  "api_keys": {
    "admin-key": "sha256:replace-with-actual-hash"
  },
  "settings": {
    "max_command_output": "100kb",
    "command_timeout_seconds": 300,
    "log_file": "ssh-executions.log",
    "max_log_file_size_mb": 50,
    "max_log_backup_count": 10,
    "watcher_interval_seconds": 15
  }
}
```

### 6. `examples/config-sudo.json`
Single target with sudo_allowed:
```json
{
  "version": 1,
  "ssh_targets": [
    {
      "name": "app-server",
      "host": "10.0.2.50",
      "username": "ops",
      "port": 22,
      "auth": {
        "type": "key",
        "key_filename": "/home/ops/.ssh/id_ed25519"
      },
      "sudo_allowed": true
    }
  ],
  "block_patterns": ["rm\\s+-rf\\s+/", ">:\\s*/dev/sda", "mkfs\\.", "dd\\s+if="],
  "allowed_commands": {
    "default": ["systemctl", "journalctl", "docker", "uptime", "df", "free"]
  },
  "api_keys": {},
  "settings": {
    "max_command_output": "50kb",
    "command_timeout_seconds": 300
  }
}
```

### 7. `examples/config-network-auth.json`
Configuration demonstrating network-based authorization:
```json
{
  "version": 1,
  "ssh_targets": [
    {
      "name": "monitoring-target",
      "host": "monitoring.internal",
      "username": "nagios",
      "port": 22,
      "auth": { "type": "key", "key_filename": "/home/nagios/.ssh/id_ed25519" },
      "sudo_allowed": false
    }
  ],
  "block_patterns": ["rm\\s+-rf", "shutdown", "reboot"],
  "allowed_commands": {
    "default": ["uptime"],
    "networks": {
      "10.0.100.0/24": {
        "commands": ["uptime", "df", "free", "ps", "ss", "netstat", "systemctl status *"],
        "description": "Monitoring subnet — extended health checks"
      },
      "192.168.1.0/24": {
        "commands": ["uptime", "df", "free"],
        "description": "Office subnet — basic health checks"
      }
    }
  },
  "api_keys": {},
  "settings": {
    "max_command_output": "50kb",
    "command_timeout_seconds": 60
  }
}
```

### 8. `examples/curl-examples.sh`
```bash
#!/bin/bash
# Direct MCP JSON-RPC examples for testing
# Replace URL and API key as needed

BASE_URL="https://localhost/mcp-ssh"
API_KEY="your-api-key-here"

# List all configured SSH targets
echo "=== ssh_list_servers ==="
curl -s -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssh_list_servers"}}' | jq .

# List commands allowed for this caller
echo "=== ssh_list_allowed_commands ==="
curl -s -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ssh_list_allowed_commands","arguments":{"server_name":"web-server"}}}' | jq .

# Execute a command
echo "=== ssh_execute_command ==="
curl -s -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_execute_command","arguments":{"server_name":"web-server","command":"uptime"}}}' | jq .

# Download a file
echo "=== ssh_download_file ==="
curl -s -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ssh_download_file","arguments":{"server_name":"web-server","remote_path":"/var/log/syslog"}}}' | jq .
```

### 9. `examples/mcp-client-example.py`
```python
"""
Example MCP client using fastmcp for interacting with mcp-ssh server.

Requirements: pip install fastmcp
"""
import asyncio
from fastmcp import Client


async def main():
    async with Client("https://localhost/mcp-ssh", headers={
        "X-API-Key": "your-api-key-here"
    }) as client:
        # List available servers
        servers = await client.call_tool("ssh_list_servers")
        print("Servers:", servers)

        # List allowed commands
        allowed = await client.call_tool(
            "ssh_list_allowed_commands",
            {"server_name": "web-server"}
        )
        print("Allowed commands:", allowed)

        # Execute a command
        result = await client.call_tool(
            "ssh_execute_command",
            {"server_name": "web-server", "command": "df -h"}
        )
        print("Command output:", result)


if __name__ == "__main__":
    asyncio.run(main())
```

### 10. Create `config-schema.json`
JSON Schema for the configuration file format, enabling IDE autocompletion and validation:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://mcp-ssh.local/schemas/config.json",
  "title": "MCP-SSH Configuration",
  "description": "Configuration schema for the MCP-SSH server",
  "type": "object",
  "required": ["version", "ssh_targets", "block_patterns", "allowed_commands", "settings"],
  "properties": {
    "version": {
      "type": "integer",
      "description": "Config schema version (currently 1)"
    },
    "ssh_targets": {
      "type": "array",
      "description": "SSH target server definitions",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["name", "host", "username", "auth"],
        "properties": {
          "name": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9._-]{1,128}$",
            "description": "Unique target identifier"
          },
          "host": {
            "type": "string",
            "description": "SSH server hostname or IP address"
          },
          "username": {
            "type": "string",
            "description": "SSH login username"
          },
          "port": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535,
            "default": 22,
            "description": "SSH server port"
          },
          "auth": {
            "type": "object",
            "required": ["type"],
            "oneOf": [
              {
                "properties": {
                  "type": { "const": "key" },
                  "key_filename": { "type": "string" }
                },
                "required": ["key_filename"]
              },
              {
                "properties": {
                  "type": { "const": "password" },
                  "password": { "type": "string" }
                },
                "required": ["password"]
              }
            ]
          },
          "sudo_allowed": {
            "type": "boolean",
            "default": false,
            "description": "Allow sudo commands on this target"
          }
        }
      }
    },
    "block_patterns": {
      "type": "array",
      "description": "Regex patterns for commands that are always denied",
      "items": { "type": "string" }
    },
    "allowed_commands": {
      "type": "object",
      "required": ["default"],
      "properties": {
        "default": {
          "type": "array",
          "items": { "type": "string" }
        },
        "api_keys": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "required": ["commands"],
            "properties": {
              "commands": {
                "type": "array",
                "items": { "type": "string" }
              },
              "description": { "type": "string" }
            }
          }
        },
        "networks": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "required": ["commands"],
            "properties": {
              "commands": {
                "type": "array",
                "items": { "type": "string" }
              },
              "description": { "type": "string" }
            }
          }
        }
      }
    },
    "api_keys": {
      "type": "object",
      "description": "SHA-256 hashed API keys (sha256: prefix)",
      "additionalProperties": {
        "type": "string",
        "pattern": "^sha256:[a-f0-9]{64}$"
      }
    },
    "settings": {
      "type": "object",
      "properties": {
        "max_command_output": {
          "type": "string",
          "pattern": "^\\d+(b|kb|mb|gb)$",
          "default": "50kb"
        },
        "command_timeout_seconds": {
          "type": "integer",
          "minimum": 1,
          "maximum": 3600,
          "default": 120
        },
        "log_file": {
          "type": "string",
          "default": "ssh-executions.log"
        },
        "max_log_file_size_mb": {
          "type": "integer",
          "minimum": 1,
          "maximum": 10000,
          "default": 10
        },
        "max_log_backup_count": {
          "type": "integer",
          "minimum": 0,
          "maximum": 100,
          "default": 5
        },
        "watcher_interval_seconds": {
          "type": "integer",
          "minimum": 1,
          "maximum": 3600,
          "default": 15
        }
      }
    }
  }
}
```

### 11. Create `LICENSE`
MIT License (recommended — simple, permissive, industry standard):

```
MIT License

Copyright (c) [year] [copyright holder]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Dependencies
- Task 15a (README, ARCHITECTURE, SECURITY, CONTRIBUTING — examples reference these docs)
- Task 11a (config schema migration — JSON Schema relates to the config format)

## Acceptance Criteria
- `examples/` directory exists with 6 example files + README
- `claude-desktop-config.json` ready for users to copy and modify
- `curl-examples.sh` demonstrates all 5 MCP tools
- `mcp-client-example.py` shows programmatic client usage
- `config-schema.json` validates the configuration format
- `default-config.json` references `$schema` for IDE autocompletion
- Four example configs cover: basic, multi-target, sudo, and network auth scenarios
- `LICENSE` file present (MIT)
