# Plan 01: Docker & Compose Best Practices

## Master Plan — contains all context needed for implementation

---

## Current State

### `Dockerfile` (existing)
```dockerfile
FROM python:3.13-alpine
RUN pip install fastmcp paramiko
WORKDIR /app
COPY server.py ssh-servers.json ssh_key ssh_key.pub /app/
RUN chmod 600 /app/ssh_key
CMD ["python3", "/app/server.py"]
```

### `compose.yaml` (existing)
```yaml
services:
  mcp-ssh:
    image: mcp-ssh:local
    container_name: mcp-ssh
    restart: unless-stopped
    networks:
      - traefik
    labels:
      traefik.enable: "true"
      traefik.http.routers.mcp-ssh.entrypoints: "https"
      traefik.http.routers.mcp-ssh.tls: "true"
      traefik.http.routers.mcp-ssh.rule: "Host(`ssh-mcp.gelse.local`)"
      traefik.http.routers.mcp-ssh.service: "mcp-ssh"
      traefik.http.services.mcp-ssh.loadbalancer.server.port: "8080"
      traefik.docker.network: "traefik"

networks:
  traefik:
    external: true
```

## Problems

| # | Issue | Detail |
|---|-------|--------|
| 1 | **compose does not reference Dockerfile** | `compose.yaml` uses `image: mcp-ssh:local` which assumes a pre-built image. It should use `build:` to reference the Dockerfile directly, enabling `docker compose up --build`. |
| 2 | **secrets copied into image** | `ssh_key` and `ssh_key.pub` are copied into the Docker image via `COPY`. This is a security risk — anyone with access to the image can extract the private key. Secrets should be mounted at runtime. |
| 3 | **no .dockerignore** | Without a `.dockerignore`, the build context may include unnecessary files (`.git/`, `__pycache__/`, `plans/`, etc.), slowing builds and potentially leaking sensitive data. |
| 4 | **no healthcheck** | No HEALTHCHECK in Dockerfile or healthcheck in compose makes it harder for orchestrators to detect if the service is actually working. |
| 5 | **no config volume mount** | The new config directory (`/config`) needs to be mounted as a volume so the config file persists outside the container. |
| 6 | **no logging volume mount** | The new log file(s) need a volume mount so logs persist outside the container. |

## Proposed Changes

### 1. Rewrite `Dockerfile`

```dockerfile
FROM python:3.13-alpine

# Create non-root user for security
RUN addgroup -S mcpssh && adduser -S mcpssh -G mcpssh

# Install dependencies
RUN pip install --no-cache-dir fastmcp paramiko

WORKDIR /app

# Copy application code only (not secrets!)
COPY server.py /app/
COPY lib/ /app/lib/          # new modular code structure

# Create directories for config and logs
RUN mkdir -p /config /logs && chown -R mcpssh:mcpssh /app /config /logs

USER mcpssh

# Config directory can be overridden via environment variable
ENV CONFIG_DIR=/config
ENV LOG_DIR=/logs

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["python3", "/app/server.py"]
```

### 2. Rewrite `compose.yaml`

```yaml
services:
  mcp-ssh:
    build:
      context: .
      dockerfile: Dockerfile
    image: mcp-ssh:local
    container_name: mcp-ssh
    restart: unless-stopped
    volumes:
      - ./config:/config          # config file(s)
      - ./logs:/logs              # log output
      - ./ssh_key:/app/ssh_key:ro   # secrets mounted at runtime, read-only
      - ./ssh_key.pub:/app/ssh_key.pub:ro
      - ./ssh-servers.json:/app/ssh-servers.json:ro
    environment:
      - CONFIG_DIR=/config
      - LOG_DIR=/logs
    networks:
      - traefik
    labels:
      traefik.enable: "true"
      traefik.http.routers.mcp-ssh.entrypoints: "https"
      traefik.http.routers.mcp-ssh.tls: "true"
      traefik.http.routers.mcp-ssh.rule: "Host(`ssh-mcp.gelse.local`)"
      traefik.http.routers.mcp-ssh.service: "mcp-ssh"
      traefik.http.routers.mcp-ssh.middlewares: "mcp-ssh-headers"
      traefik.http.middlewares.mcp-ssh-headers.headers.customrequestheaders.X-Forwarded-For: ""
      traefik.http.services.mcp-ssh.loadbalancer.server.port: "8080"
      traefik.docker.network: "traefik"

networks:
  traefik:
    external: true
```

**Note on `X-Forwarded-For`**: Traefik v3 should pass `X-Forwarded-For` automatically when `trustedIPs` are configured. If not, the middleware above ensures it. Verify with your Traefik configuration.

### 3. Create `.dockerignore`

```
.git/
__pycache__/
*.pyc
*.pyo
.env
.plans/
plans/
logs/
config/
*.md
!Dockerfile
```

## Implementation Steps

1. Create [`lib/`](lib/) directory structure (code modularization done in plans 02-04 will populate this)
2. Rewrite [`Dockerfile`](Dockerfile) with multi-stage considerations, non-root user, healthcheck
3. Rewrite [`compose.yaml`](compose.yaml) to use `build:` directive, add volume mounts, add Traefik middleware for `X-Forwarded-For`
4. Create [`.dockerignore`](.dockerignore)
5. Create [`lib/health.py`](lib/health.py) — a simple HTTP health endpoint reachable at `/health`
6. Update [`server.py`](server.py) to add the `/health` route
7. Test: `docker compose build && docker compose up`
