# Quality gates and day-to-day tasks. `make check` runs everything a change must pass.
# Needs: Foundry (forge, anvil), uv, Docker. Run `make help` for the list.

SHELL := /bin/bash
.DEFAULT_GOAL := help

CONTRACTS := contracts
SERVICE   := service
COMPOSE   := docker compose
HELM      := docker run --rm -v $(CURDIR)/deploy/helm/dataledger:/chart:ro alpine/helm:4.3.2
SLITHER   := uvx --from slither-analyzer==0.11.6 slither

.PHONY: help
help: ## List the targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------------------------- setup

.PHONY: install
install: ## Fetch contract libraries and the Python environment
	git submodule update --init --recursive
	cd $(SERVICE) && uv sync --all-extras

.PHONY: build
build: ## Compile the contracts
	cd $(CONTRACTS) && forge build

# ---------------------------------------------------------------------------------------------- gates

.PHONY: check
check: lint abi-check test gas-check slither helm-lint ## Every gate: lint, ABIs, tests, gas, static analysis, chart

.PHONY: lint
lint: ## Formatting, linters and type checks for both languages
	cd $(CONTRACTS) && forge fmt --check && forge lint
	cd $(SERVICE) && uv run ruff check . && uv run ruff format --check . && uv run mypy

.PHONY: fmt
fmt: ## Format both code bases
	cd $(CONTRACTS) && forge fmt
	cd $(SERVICE) && uv run ruff format . && uv run ruff check --fix .

.PHONY: test
test: test-contracts test-service ## All tests

.PHONY: test-contracts
test-contracts: ## Unit, fuzz and invariant tests
	cd $(CONTRACTS) && FOUNDRY_PROFILE=ci forge test

.PHONY: test-service
test-service: build ## Python unit and end-to-end tests (starts anvil), with coverage
	cd $(SERVICE) && uv run pytest --cov

.PHONY: test-postgres
test-postgres: build ## End-to-end tests against PostgreSQL 18 in Docker
	docker rm -f dataledger-test-pg >/dev/null 2>&1 || true
	docker run -d --name dataledger-test-pg -e POSTGRES_USER=dl -e POSTGRES_PASSWORD=dl -e POSTGRES_DB=dl \
		-p 55432:5432 postgres:18-alpine >/dev/null
	until docker exec dataledger-test-pg pg_isready -U dl -q; do sleep 1; done
	cd $(SERVICE) && DATALEDGER_TEST_DATABASE_URL=postgresql+psycopg://dl:dl@127.0.0.1:55432/dl \
		uv run pytest tests/integration; status=$$?; docker rm -f dataledger-test-pg >/dev/null; exit $$status

.PHONY: coverage
coverage: ## Contract coverage summary
	cd $(CONTRACTS) && forge coverage --report summary --no-match-coverage "(test|script)"

.PHONY: abi
abi: build ## Copy contract ABIs into the service package
	python3 scripts/export_abi.py

.PHONY: abi-check
abi-check: abi ## Fail when the committed ABIs drift from the contracts
	git diff --exit-code -- $(SERVICE)/src/dataledger/abi

.PHONY: gas
gas: ## Refresh the gas snapshot
	cd $(CONTRACTS) && forge snapshot --no-match-test "invariant|testFuzz"

.PHONY: gas-check
gas-check: ## Fail when gas use changes without a new snapshot
	cd $(CONTRACTS) && forge snapshot --check --no-match-test "invariant|testFuzz"

.PHONY: slither
slither: ## Static analysis of the contracts
	cd $(CONTRACTS) && $(SLITHER) . --config-file slither.config.json

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart with both value profiles
	$(HELM) lint /chart --strict -f /chart/ci/s3-values.yaml
	$(HELM) lint /chart --strict -f /chart/ci/local-values.yaml

# ---------------------------------------------------------------------------------------------- run

.PHONY: up
up: ## Start chain, deployment, PostgreSQL, API and indexer
	$(COMPOSE) up -d --wait

.PHONY: reference-data
reference-data: ## Play the governance scenario against the running stack
	$(COMPOSE) --profile reference-data run --rm reference-data

.PHONY: observability
observability: ## Add Prometheus (:9090) and Grafana (:3000)
	$(COMPOSE) --profile observability up -d

.PHONY: down
down: ## Stop the stack and delete its volumes
	$(COMPOSE) --profile observability --profile reference-data down -v

# ---------------------------------------------------------------------------------------------- release

.PHONY: images
images: ## Build both images for the local platform
	REVISION=$$(git rev-parse --short HEAD) CREATED=$$(date -u +%Y-%m-%dT%H:%M:%SZ) PLATFORMS=linux/$$(docker version -f '{{.Server.Arch}}') \
		docker buildx bake -f docker-bake.hcl --load

.PHONY: release-images
release-images: ## Build linux/amd64 + linux/arm64 with SBOM and provenance, and push
	REVISION=$$(git rev-parse --short HEAD) CREATED=$$(date -u +%Y-%m-%dT%H:%M:%SZ) docker buildx bake -f docker-bake.hcl --push

.PHONY: diagrams
diagrams: ## Render README diagrams from docs/diagrams/*.mmd
	cd $(SERVICE) && uv run --with playwright python ../scripts/render_diagrams.py

.PHONY: screenshots
screenshots: ## Capture console (and Grafana) screenshots from the running stack
	cd $(SERVICE) && uv run --with playwright python ../scripts/capture_screenshots.py
