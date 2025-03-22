.PHONY: all build build-release test clean run lint doc install uninstall help scan worker
.DEFAULT_GOAL := help

CARGO := cargo
BINARY := fatt
INSTALL_DIR := $(HOME)/.local/bin
DATABASE := results.sqlite
DOMAINS_FILE := domains.txt
RULES_FILE := rules.yaml
LOG_DIR := logs
ZSHRC := $(HOME)/.zshrc

# Colors for pretty output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

all: build ## Build the project in debug mode

build: ## Build the project in debug mode
	@echo "$(BLUE)Building $(BINARY) in debug mode...$(RESET)"
	@$(CARGO) build

build-release: ## Build the project in release mode
	@echo "$(BLUE)Building $(BINARY) in release mode...$(RESET)"
	@$(CARGO) build --release

test: ## Run tests
	@echo "$(BLUE)Running tests...$(RESET)"
	@$(CARGO) test

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	@$(CARGO) clean
	@echo "$(BLUE)Cleaning database and logs...$(RESET)"
	@rm -f $(DATABASE)
	@rm -rf $(LOG_DIR)
	@rm -rf cache

run: build ## Run the application
	@echo "$(BLUE)Running $(BINARY)...$(RESET)"
	@$(CARGO) run

lint: ## Run clippy lints
	@echo "$(BLUE)Running linter...$(RESET)"
	@$(CARGO) clippy --all-targets --all-features

fix: ## Fix lints automatically
	@echo "$(BLUE)Fixing lints...$(RESET)"
	@$(CARGO) fix --allow-dirty
	@$(CARGO) clippy --fix --allow-dirty

doc: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(RESET)"
	@$(CARGO) doc --no-deps
	@echo "$(GREEN)Documentation available at: file://$(shell pwd)/target/doc/$(BINARY)/index.html$(RESET)"

install: build-release ## Install the application to user's local bin and update .zshrc
	@echo "$(BLUE)Installing $(BINARY) to $(INSTALL_DIR)...$(RESET)"
	@mkdir -p $(INSTALL_DIR)
	@cp target/release/$(BINARY) $(INSTALL_DIR)/
	@echo "$(BLUE)Updating $(ZSHRC)...$(RESET)"
	@if ! grep -q "# FATT Security Scanner" $(ZSHRC); then \
		echo '\n# FATT Security Scanner' >> $(ZSHRC); \
		echo 'export PATH=$$PATH:$(INSTALL_DIR)' >> $(ZSHRC); \
	fi
	@echo "$(GREEN)Installation complete. Run 'source $(ZSHRC)' to update your current shell or start a new terminal.$(RESET)"

uninstall: ## Uninstall the application and remove entries from .zshrc
	@echo "$(BLUE)Uninstalling $(BINARY)...$(RESET)"
	@rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "$(BLUE)Removing entries from $(ZSHRC)...$(RESET)"
	@sed -i '/# FATT Security Scanner/,+2d' $(ZSHRC) 2>/dev/null || true
	@echo "$(GREEN)Uninstallation complete. Run 'source $(ZSHRC)' to update your current shell.$(RESET)"

scan: build ## Run a scan with default settings
	@echo "$(BLUE)Running scan with default settings...$(RESET)"
	@mkdir -p $(LOG_DIR)
	@target/debug/$(BINARY) scan -i $(DOMAINS_FILE) -r $(RULES_FILE)

worker-start: build ## Start a worker node
	@echo "$(BLUE)Starting worker node...$(RESET)"
	@mkdir -p $(LOG_DIR)
	@echo "$(YELLOW)Usage: make worker-start MASTER=host:port [WORKER_ID=unique-id]$(RESET)"
	@if [ -z "$(MASTER)" ]; then \
		echo "$(RED)Error: MASTER address not specified. Use MASTER=host:port$(RESET)"; \
		exit 1; \
	fi
	@if [ -z "$(WORKER_ID)" ]; then \
		target/debug/$(BINARY) worker start -m $(MASTER); \
	else \
		target/debug/$(BINARY) worker start -m $(MASTER) -i $(WORKER_ID); \
	fi

worker-stop: build ## Stop worker nodes
	@echo "$(BLUE)Stopping worker node...$(RESET)"
	@echo "$(YELLOW)Usage: make worker-stop [WORKER_ID=unique-id]$(RESET)"
	@if [ -z "$(WORKER_ID)" ]; then \
		target/debug/$(BINARY) worker stop -i all; \
	else \
		target/debug/$(BINARY) worker stop -i $(WORKER_ID); \
	fi

export-results: build ## Export scan results
	@echo "$(BLUE)Exporting scan results...$(RESET)"
	@echo "$(YELLOW)Usage: make export-results [FORMAT=csv|json] [OUTPUT=results.csv]$(RESET)"
	@if [ -z "$(FORMAT)" ]; then \
		FORMAT="csv"; \
	fi
	@if [ -z "$(OUTPUT)" ]; then \
		OUTPUT="results.$(FORMAT)"; \
	fi
	@target/debug/$(BINARY) results export -d $(DATABASE) -o $(OUTPUT) -f $(FORMAT)
	@echo "$(GREEN)Results exported to $(OUTPUT)$(RESET)"

setup-dev: ## Set up development environment
	@echo "$(BLUE)Setting up development environment...$(RESET)"
	@rustup component add clippy rustfmt
	@echo "$(GREEN)Development environment setup complete.$(RESET)"

cache-flush: build ## Flush DNS cache
	@echo "$(BLUE)Flushing DNS cache...$(RESET)"
	@target/debug/$(BINARY) dns flush

cache-status: build ## Show DNS cache status
	@echo "$(BLUE)Showing DNS cache status...$(RESET)"
	@target/debug/$(BINARY) dns status

help: ## Display this help message
	@echo "$(BLUE)FATT - Find All The Things$(RESET)"
	@echo "$(BLUE)A high-performance, distributed security scanning tool$(RESET)"
	@echo ""
	@echo "$(YELLOW)Usage:$(RESET)"
	@echo "  make $(GREEN)<target>$(RESET)"
	@echo ""
	@echo "$(YELLOW)Targets:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'
