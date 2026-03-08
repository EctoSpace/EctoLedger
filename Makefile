.PHONY: start setup rebuild backend reset-db test test-integration test-enclave test-enclave-hv check clean help

# Detect platform for Unix launchers (macOS vs Linux)
# On Windows (MSYS/MINGW/CYGWIN), delegate to the PowerShell launcher.
ifneq (,$(findstring MINGW,$(shell uname -s))$(findstring MSYS,$(shell uname -s))$(findstring CYGWIN,$(shell uname -s)))
  ECTO_LAUNCH := pwsh -File ./ectoledger-win.ps1
else
  ECTO_LAUNCH := ./$(if $(filter Darwin,$(shell uname -s)),ectoledger-mac,ectoledger-linux)
endif

start: ## Start backend + Tauri GUI (default)
	$(ECTO_LAUNCH)

setup: ## Build binary + install npm deps (no servers started)
	$(ECTO_LAUNCH) --setup

rebuild: ## Force rebuild of Rust binary, then start
	$(ECTO_LAUNCH) --rebuild

backend: ## Start backend server only (no GUI)
	$(ECTO_LAUNCH) --backend-only

reset-db: ## Wipe embedded Postgres data dir (fixes auth failures after partial first run)
	$(ECTO_LAUNCH) --reset-db --setup

test: ## Run all Rust unit tests
	cargo test --workspace

test-integration: ## Run integration tests against ephemeral Postgres (requires Docker)
	./scripts/test-integration.sh

test-enclave: ## Run enclave IPC + remote attestation unit tests (no hardware required)
	cargo test --features enclave -p ectoledger --lib -- enclave::ipc::tests --nocapture
	cargo test --features enclave -p ectoledger --test enclave_ipc -- --nocapture
	cargo test --features enclave-remote -p ectoledger --lib -- enclave::remote::tests --nocapture

test-enclave-hv: ## Run Apple Hypervisor enclave boot tests (macOS Apple Silicon, requires codesigning)
	cargo test --features sandbox-apple-enclave --no-run
	@BIN=$$(ls -t target/debug/deps/enclave_apple_boot-* | grep -v '\\.' | head -1) && \
		echo "Codesigning $$BIN" && \
		codesign -s - --entitlements entitlements.xml --force "$$BIN" && \
		"$$BIN" --nocapture

check: ## Type-check the Svelte/TypeScript GUI
	cd gui && npm run check

clean: ## Remove build artifacts and node_modules
	cargo clean
	rm -rf gui/node_modules gui/dist gui/src-tauri/target

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := start
