# 08b - Add Log Output Truncation, Rotation Compression, and Metrics Endpoint

**Parent Plan**: [08-logging-observability.md](plans/08-logging-observability.md)

## Objective
Add separate log output truncation (distinct from response truncation), gzip compression for rotated log files, and a Prometheus metrics endpoint.

## Implementation Steps
1. Add `max_log_output` setting to config schema (default: 4096 characters)
2. In log event emission, truncate output field at `max_log_output`:
   - Append `"... [truncated, full output length: N bytes]"` if truncated
   - Never truncate metadata fields, only the `output` content
3. Add `compress_rotated` setting (default: true)
4. In `FileLogger._rotate_if_needed()`, after renaming file, gzip it:
   ```python
   import gzip, shutil
   with open(rotated_path, 'rb') as f_in:
       with gzip.open(rotated_path + '.gz', 'wb') as f_out:
           shutil.copyfileobj(f_in, f_out)
   os.remove(rotated_path)
   ```
5. Add Prometheus metrics:
   - Install `prometheus_client` dependency
   - Create `lib/metrics.py` with counters and histograms:
     - `mcpssh_requests_total{tool, status}`
     - `mcpssh_ssh_connections_total{target}`
     - `mcpssh_ssh_connection_duration_seconds{target}`
     - `mcpssh_auth_denials_total{reason}`
     - `mcpssh_command_duration_seconds{target}`
   - Expose on `/metrics` via `mcp.custom_route`
   - Add `OPTIONS /metrics` for CORS

## Dependencies
- Task 08a (logging integration)

## Acceptance Criteria
- Command output truncated in logs at `max_log_output` with truncation marker
- Rotated log files are gzip-compressed
- `/metrics` endpoint returns Prometheus-format metrics
- Counters increment correctly for each tool call
- Histograms track SSH connection and command duration
