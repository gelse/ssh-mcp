FROM python:3.13-alpine

# Create non-root user for security
RUN addgroup -S mcpssh && adduser -S mcpssh -G mcpssh

# Install dependencies
RUN pip install --no-cache-dir fastmcp paramiko

WORKDIR /app

# Copy application code only (not secrets!)
COPY server.py /app/
COPY lib/ /app/lib/
COPY default-config.json /app/

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
