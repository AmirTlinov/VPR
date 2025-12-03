# VPR VPN - Development Makefile
#
# Usage:
#   make help        - Show this help
#   make build       - Build debug binaries
#   make release     - Build release binaries
#   make test        - Run all tests
#   make docker      - Build Docker images
#   make docker-test - Run Docker integration tests
#   make lint        - Run clippy lints
#   make fmt         - Format code
#   make clean       - Clean build artifacts

.PHONY: help build release test lint fmt clean docker docker-test docker-push
.DEFAULT_GOAL := help

# Configuration
CARGO := cargo
DOCKER := docker
COMPOSE := docker compose
DOCKER_REGISTRY ?= ghcr.io/amirtlinov/vpr
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Colors
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

# =============================================================================
# Help
# =============================================================================

help: ## Show this help
	@echo "$(CYAN)VPR VPN Development Commands$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'

# =============================================================================
# Build
# =============================================================================

build: ## Build debug binaries
	$(CARGO) build --workspace

release: ## Build release binaries
	$(CARGO) build --release --package masque-core --bin vpn-server --bin vpn-client

server: ## Build vpn-server only
	$(CARGO) build --release --package masque-core --bin vpn-server

client: ## Build vpn-client only
	$(CARGO) build --release --package masque-core --bin vpn-client

# =============================================================================
# Test
# =============================================================================

test: ## Run all tests
	$(CARGO) test --workspace

test-unit: ## Run unit tests only
	$(CARGO) test --workspace --lib

test-integration: ## Run integration tests
	$(CARGO) test --workspace --test '*'

test-doc: ## Run documentation tests
	$(CARGO) test --workspace --doc

bench: ## Run benchmarks
	$(CARGO) bench --package masque-core

coverage: ## Generate code coverage report
	$(CARGO) llvm-cov --workspace --html --output-dir coverage

# =============================================================================
# Lint & Format
# =============================================================================

lint: ## Run clippy lints
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt: ## Format code
	$(CARGO) fmt --all

fmt-check: ## Check code formatting
	$(CARGO) fmt --all -- --check

audit: ## Run security audit
	$(CARGO) audit

check: fmt-check lint test-unit ## Run all checks (CI-like)

# =============================================================================
# Docker
# =============================================================================

docker: docker-server docker-client ## Build all Docker images

docker-server: ## Build vpn-server Docker image
	$(DOCKER) build --target server -t $(DOCKER_REGISTRY)/vpn-server:$(VERSION) -f docker/Dockerfile .

docker-client: ## Build vpn-client Docker image
	$(DOCKER) build --target client -t $(DOCKER_REGISTRY)/vpn-client:$(VERSION) -f docker/Dockerfile .

docker-test: ## Run Docker integration tests
	$(COMPOSE) -f docker/docker-compose.test.yml up --build --abort-on-container-exit

docker-test-build: ## Build test images only
	$(COMPOSE) -f docker/docker-compose.test.yml build

docker-down: ## Stop Docker containers
	$(COMPOSE) -f docker/docker-compose.test.yml down -v

docker-push: ## Push Docker images to registry
	$(DOCKER) push $(DOCKER_REGISTRY)/vpn-server:$(VERSION)
	$(DOCKER) push $(DOCKER_REGISTRY)/vpn-client:$(VERSION)

# =============================================================================
# Keys & Certificates
# =============================================================================

keygen: ## Generate Noise keypairs
	@mkdir -p secrets
	$(CARGO) run --release --package masque-core --bin vpn-server -- keygen --dir secrets --name server
	$(CARGO) run --release --package masque-core --bin vpn-server -- keygen --dir secrets --name client
	@echo "$(GREEN)Keys generated in secrets/$(RESET)"

cert: ## Generate self-signed TLS certificate
	@mkdir -p secrets
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout secrets/server.key -out secrets/server.crt \
		-days 365 -nodes -subj "/CN=vpn-server" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "$(GREEN)Certificate generated in secrets/$(RESET)"

# =============================================================================
# Clean
# =============================================================================

clean: ## Clean build artifacts
	$(CARGO) clean
	rm -rf coverage/
	rm -f lcov.info

clean-docker: ## Clean Docker images and volumes
	$(COMPOSE) -f docker/docker-compose.test.yml down -v --rmi local
	$(DOCKER) image prune -f

clean-all: clean clean-docker ## Clean everything

# =============================================================================
# Development
# =============================================================================

dev-server: release ## Run VPN server locally (requires sudo)
	@echo "$(YELLOW)Starting VPN server (requires sudo)...$(RESET)"
	sudo ./target/release/vpn-server \
		--bind 0.0.0.0:4433 \
		--tun-name vpr0 \
		--tun-addr 10.9.0.1 \
		--pool-start 10.9.0.2 \
		--pool-end 10.9.0.254 \
		--noise-dir secrets \
		--noise-name server \
		--cert secrets/server.crt \
		--key secrets/server.key \
		--enable-forwarding

dev-client: release ## Run VPN client locally (requires sudo)
	@echo "$(YELLOW)Starting VPN client (requires sudo)...$(RESET)"
	sudo ./target/release/vpn-client \
		--server 127.0.0.1:4433 \
		--server-name localhost \
		--server-pub secrets/server.noise.pub \
		--noise-dir secrets \
		--noise-name client \
		--insecure

watch: ## Watch for changes and rebuild
	$(CARGO) watch -x 'check --workspace'

# =============================================================================
# Documentation
# =============================================================================

doc: ## Build documentation
	$(CARGO) doc --workspace --no-deps

doc-open: doc ## Build and open documentation
	$(CARGO) doc --workspace --no-deps --open
