# Observability

ssh-mcp exposes health checks, Prometheus metrics, and structured
JSONL logging for monitoring and debugging.

---

## Health endpoint

```
GET /health
```

Returns `{"status": "ok"}` with an optional `connection_pool`
object showing aggregate pool statistics.

```bash
curl http://localhost:9080/health
# → {"status": "ok", "connection_pool": {...}}
```

The Docker healthcheck uses this endpoint:

```yaml
healthcheck:
  test: ["CMD", "wget", "--spider", "-q",
         "http://127.0.0.1:8080/health"]
  interval: 30s
  timeout: 5s
```

---

## Prometheus metrics

```
GET /metrics
```

Returns metrics in Prometheus exposition format. CORS headers
are included for cross-origin scraping.

### Metric reference

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `mcpssh_requests_total` | Counter | `tool`, `status` | Total MCP tool requests |
| `mcpssh_ssh_connections_total` | Counter | `target` | Successful SSH connections |
| `mcpssh_ssh_connection_duration_seconds` | Histogram | `target` | SSH establishment latency |
| `mcpssh_auth_denials_total` | Counter | `reason` | Authorization denials |
| `mcpssh_command_duration_seconds` | Histogram | `target` | Remote command execution time |
| `mcpssh_pool_active_connections` | Gauge | `target` | Active pool connections per target |
| `mcpssh_pool_idle_connections` | Gauge | `target` | Idle pool connections per target |
| `mcpssh_pool_created_total` | Counter | `target` | Total connections created per target |

---

## Logging

ssh-mcp uses structured JSONL logging. Every log entry includes:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 UTC timestamp |
| `event` | Event type (e.g. `ssh.execute`, `auth.denied`) |
| `request_id` | Correlation ID for request tracing |
| `log_level` | Python log level |
| `log_format_version` | Schema version (currently `1`) |

### Log targets

Configure via `settings.logging.log_targets` in the config:

```json
{
  "settings": {
    "logging": {
      "log_targets": [
        { "target": "stdout" },
        { "target": "jsonfile", "path": "/logs/ssh-mcp.log" },
        { "target": "file", "path": "/logs/ssh-mcp.log" }
      ]
    }
  }
}
```

| Target | Description |
|--------|-------------|
| `stdout` | Structured text output to stdout |
| `jsonfile` | JSONL file with rotation and gzip |
| `file` | Plain text file with rotation |

### Log rotation

| Setting | Default | Description |
|---------|---------|-------------|
| `max_log_output` | `4096` | Max chars for output field |
| `compress_rotated` | `true` | gzip rotated backups |
| `max_file_size_mb` | `10` | Max file size before rotation |
| `backup_count` | `5` | Rotated files to keep |

### Request correlation

Every request gets a unique `request_id` (UUID) that appears in
all log entries for that request. This enables end-to-end tracing
across authorization, execution, and response stages.

---

## Accessing logs

Logs are written to the mounted volume:

```yaml
volumes:
  - ./logs:/logs
```

The active log file is at `/logs/ssh-mcp.log` inside the container.
Rotated files are compressed with gzip (`.gz` extension).
