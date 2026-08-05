.PHONY: build up down test integrationtest clean-test

build:  ## Build the Docker image using docker compose
	docker compose build

up:  ## Start the service with docker compose (detached)
	docker compose up -d

down:  ## Stop and remove containers, networks
	docker compose down

test:  ## Run unit tests only (excludes integration tests)
	python -m pytest tests/ -v --ignore=tests/integration/

integrationtest:  ## Build :test image and run integration tests
	docker build -t mcp-ssh:test .
	python -m pytest tests/integration/ -v

clean-test:  ## Remove leftover test containers and network
	-docker rm -f mcp-ssh-test-app mcp-ssh-test-ssh 2>/dev/null || true
	-docker network rm mcp-ssh-test-net 2>/dev/null || true
