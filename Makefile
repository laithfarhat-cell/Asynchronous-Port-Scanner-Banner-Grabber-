# Developer shortcuts. `make` with no target prints this list.
.DEFAULT_GOAL := help
PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help venv install dev test lint fmt scan preview docker clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtual environment
	$(PY) -m venv $(VENV)

install: venv ## Install runtime dependencies
	$(BIN)/pip install -e .

dev: venv ## Install runtime + dev dependencies
	$(BIN)/pip install -e ".[dev]"

test: ## Run the test suite
	$(BIN)/python -m pytest -q

lint: ## Static checks
	$(BIN)/ruff check .

fmt: ## Auto-format / auto-fix
	$(BIN)/ruff check --fix . && $(BIN)/ruff format .

scan: ## Local demo scan against the loopback interface
	$(BIN)/python main.py -t 127.0.0.1 -p 1-1024 -c 200 --top-ports 100 -oA reports/demo

preview: ## Serve the local console (demo findings, signatures, CLI help) on :32929
	$(BIN)/python scripts/preview_server.py --host 0.0.0.0 --port 32929

docker: ## Build the container image
	docker build -t asynscan:1.0.0 .

clean: ## Remove caches and build artefacts
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
