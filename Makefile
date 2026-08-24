.DEFAULT_GOAL := help

.PHONY: help dockercontainer up down test config-test integrationtest clean-test

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'

dockercontainer:  ## Build the Docker image using docker compose
	docker compose build

up:  ## Start the service with docker compose (detached)
	docker compose up -d

down:  ## Stop and remove containers, networks
	docker compose down

test:  ## Run unit tests only (excludes integration tests)
	python -m pytest tests/ -v --ignore=tests/integration/

config-test:  ## Run config-api unit tests only (excludes integration tests)
	cd config-api && .venv/bin/python -m pytest tests/ -v --ignore=tests/test_integration.py 2>/dev/null || true

integrationtest:  ## Build :test image and run integration tests
	docker build -t mcp-ssh:test .
	python -m pip install -r requirements-dev.txt
	python -m pytest tests/integration/ -v

clean-test:  ## Remove leftover test containers, network, and log files
	-docker rm -f mcp-ssh-test-app mcp-ssh-test-ssh 2>/dev/null || true
	-docker network rm mcp-ssh-test-net 2>/dev/null || true
	-rm -f logs/ssh-mcp.log
