# ---------- Stage: sbom ----------
# Build-time CycloneDX SBOM generation (not shipped as a separate layer).
# Uses the same pinned base image so the musllinux hashes in
# requirements-build.txt match the wheels installed here.
FROM python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS sbom

# Install CycloneDX SBOM tooling (hash-pinned)
COPY requirements-build.txt /tmp/requirements-build.txt
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements-build.txt && \
    cyclonedx-py requirements /tmp/requirements.txt --of JSON -o /tmp/sbom.json && \
    rm /tmp/requirements-build.txt /tmp/requirements.txt

# ---------- Stage: runtime ----------
FROM python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

# Create non-root user for security
RUN addgroup -S mcpssh && adduser -S mcpssh -G mcpssh

# Install dependencies with hash-pinned requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

WORKDIR /app

# Copy application code only (not secrets!)
COPY server.py /app/
COPY lib/ /app/lib/
COPY default-config.json /app/
COPY config.schema.json /app/

# Copy CycloneDX SBOM generated at build time
COPY --from=sbom /tmp/sbom.json /app/sbom.json

# Create directories for config and logs
RUN mkdir -p /config /logs && chown -R mcpssh:mcpssh /app /config /logs

USER mcpssh

# Config directory can be overridden via environment variable
ENV CONFIG_DIR=/config
ENV LOG_DIR=/logs

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["python3", "/app/server.py", "--config", "/config", "--ssh-key", "ssh_key", "--log-dir", "/logs"]
