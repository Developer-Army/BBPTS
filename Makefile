BINARY_NAME=bbpts
CMD_PATH=./cmd/bbpts
INSTALL_PATH=/usr/local/bin
BINARY_DIR=bin
VERSION=v1.4.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Detect OS for binary extension
ifeq ($(OS),Windows_NT)
 BINARY_EXT=.exe
else
 BINARY_EXT=
endif

.PHONY: all build build-full build-fleet build-release dist test test-short test-race bench \
	lint vet fmt security doctor validate validate-framework clean install \
	install-user uninstall uninstall-user setup help coverage docker

all: build

# ─────────────────────────────────────────
# Build Targets
# ─────────────────────────────────────────

build:
	@echo " Building $(BINARY_NAME)$(BINARY_EXT)..."
	@mkdir -p $(BINARY_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/$(BINARY_NAME)$(BINARY_EXT) $(CMD_PATH)
	@echo " Build complete: ./$(BINARY_DIR)/$(BINARY_NAME)$(BINARY_EXT)"

build-full:
	@echo " Building with NATS + Redis support..."
	@mkdir -p $(BINARY_DIR)
	go build -tags nats,redis -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/$(BINARY_NAME)$(BINARY_EXT) $(CMD_PATH)
	@echo " Full build complete: ./$(BINARY_DIR)/$(BINARY_NAME)$(BINARY_EXT)"

build-fleet:
	@echo " Building fleet-enabled binary (NATS + Redis + Playwright)..."
	@mkdir -p $(BINARY_DIR)
	go build -tags nats,redis,playwright -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/$(BINARY_NAME)-fleet$(BINARY_EXT) $(CMD_PATH)
	@echo " Fleet build complete: ./$(BINARY_DIR)/$(BINARY_NAME)-fleet$(BINARY_EXT)"

build-release:
	@echo " Building release binary with optimizations..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o $(BINARY_DIR)/$(BINARY_NAME)$(BINARY_EXT) $(CMD_PATH)

# Cross-compile for all platforms → dist/
dist:
	@echo " Building all platform binaries → dist/"
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_linux_amd64          $(CMD_PATH)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_linux_arm64          $(CMD_PATH)
	CGO_ENABLED=0 GOOS=linux   GOARCH=386    go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_linux_386            $(CMD_PATH)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_darwin_amd64         $(CMD_PATH)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_darwin_arm64         $(CMD_PATH)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_windows_amd64.exe   $(CMD_PATH)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_windows_arm64.exe   $(CMD_PATH)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_freebsd_amd64       $(CMD_PATH)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_freebsd_arm64       $(CMD_PATH)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=386    go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_freebsd_386         $(CMD_PATH)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_openbsd_amd64       $(CMD_PATH)
	CGO_ENABLED=0 GOOS=openbsd GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -trimpath -o dist/bbpts_openbsd_arm64       $(CMD_PATH)
	@echo " All binaries written to ./dist/"
	@ls -lh dist/




# ─────────────────────────────────────────
# Test Targets
# ─────────────────────────────────────────

test:
	@echo " Running all tests..."
	go test -v -count=1 ./...

test-short:
	@echo " Running short tests..."
	go test -short ./...

test-race:
	@echo " Running tests with race detector..."
	go test -v -race -count=1 ./...

coverage:
	@echo " Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo " Coverage report: coverage.html"

bench:
	@echo " Running benchmarks..."
	go test -bench=. -benchmem -run=^$$ ./... | tee benchmark.txt
	@echo " Benchmark results: benchmark.txt"

# ─────────────────────────────────────────
# Code Quality
# ─────────────────────────────────────────

lint:
	@echo " Running linter..."
	golangci-lint run --timeout=5m ./...

vet:
	@echo " Running go vet..."
	go vet ./...

fmt:
	@echo " Formatting code..."
	gofmt -s -w .
	@echo " Code formatted"

security:
	@echo " Running security scan..."
	@which gosec > /dev/null 2>&1 || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -fmt=json -out=gosec-report.json ./... || true
	@echo " Security report: gosec-report.json"
	@echo " Running govulncheck..."
	@which govulncheck > /dev/null 2>&1 || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./... || true

# ─────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────

doctor: build
	@echo " Running environment diagnostics..."
	./$(BINARY_DIR)/$(BINARY_NAME)$(BINARY_EXT) -doctor

validate: build
	@echo " Validating configuration..."
	./$(BINARY_DIR)/$(BINARY_NAME)$(BINARY_EXT) -validate-config

validate-framework: build
	@echo " Running full deterministic validation framework..."
	bash tests/test.sh

# ─────────────────────────────────────────
# Setup & Install
# ─────────────────────────────────────────

install: build setup
 ifeq ($(OS),Windows_NT)
	@echo "Install target not fully supported on Windows via Makefile. Please copy $(BINARY_DIR)/$(BINARY_NAME).exe to your PATH."
 else
	@echo " Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	@if [ -w $(INSTALL_PATH) ] || sudo cp $(BINARY_DIR)/$(BINARY_NAME) $(INSTALL_PATH); then \
		echo " Installed to $(INSTALL_PATH)"; \
	else \
		echo " Failed to install to $(INSTALL_PATH). Trying $(HOME)/.local/bin..."; \
		mkdir -p $(HOME)/.local/bin && cp $(BINARY_DIR)/$(BINARY_NAME) $(HOME)/.local/bin/; \
		echo " Installed to $(HOME)/.local/bin"; \
	fi
	@echo " Setting up global configurations in $(HOME)/.bbpts..."
	@mkdir -p $(HOME)/.bbpts/wordlists $(HOME)/.bbpts/state
	@cp -n configs/config.json $(HOME)/.bbpts/ 2>/dev/null || true
	@cp -n configs/rules.json $(HOME)/.bbpts/ 2>/dev/null || true
	@cp -r wordlists/* $(HOME)/.bbpts/wordlists/
 endif

install-user: build setup
	@echo " Installing $(BINARY_NAME) to $(HOME)/.local/bin..."
	@mkdir -p $(HOME)/.local/bin
	@cp $(BINARY_DIR)/$(BINARY_NAME) $(HOME)/.local/bin/
	@echo " Installed to $(HOME)/.local/bin"
	@echo " Setting up global configurations in $(HOME)/.bbpts..."
	@mkdir -p $(HOME)/.bbpts/wordlists $(HOME)/.bbpts/state
	@cp -n configs/config.json $(HOME)/.bbpts/ 2>/dev/null || true
	@cp -n configs/rules.json $(HOME)/.bbpts/ 2>/dev/null || true
	@cp -r wordlists/* $(HOME)/.bbpts/wordlists/
	@echo " Make sure '$(HOME)/.local/bin' is in your PATH to use '$(BINARY_NAME)' globally."

uninstall-user:
	@echo " Removing $(BINARY_NAME) from $(HOME)/.local/bin..."
	@rm -f $(HOME)/.local/bin/$(BINARY_NAME)
	@echo " Removed"

uninstall:
ifeq ($(OS),Windows_NT)
	@echo "Uninstall target not supported on Windows via Makefile."
else
	@echo " Removing $(BINARY_NAME) from $(INSTALL_PATH)..."
	@sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo " Removed from $(INSTALL_PATH)"
endif

setup:
	@echo " Running cross-platform setup..."
	bash scripts/setup.sh

# ─────────────────────────────────────────
# Docker
# ─────────────────────────────────────────

docker:
	@echo " Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .
	@echo " Docker image built: $(BINARY_NAME):$(VERSION)"

# ─────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────

clean:
	@echo " Cleaning up..."
	rm -rf $(BINARY_DIR) coverage.out coverage.html benchmark.txt gosec-report.json
	go clean
	@echo " Clean"

# ─────────────────────────────────────────
# Help
# ─────────────────────────────────────────

help:
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║ BBPTS Makefile Targets ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
	@echo " Build:"
	@echo " build          Build the binary (debug)"
	@echo " build-full     Build with NATS + Redis support"
	@echo " build-fleet    Build with NATS + Redis + Playwright"
	@echo " build-release  Build optimized release binary (current platform)"
	@echo " dist           Cross-compile for Linux/macOS/Windows → dist/"
	@echo " docker         Build Docker image"
	@echo ""
	@echo " Test:"
	@echo " test Run all tests with verbose output"
	@echo " test-short Run short tests only"
	@echo " test-race Run tests with race detector"
	@echo " coverage Generate HTML coverage report"
	@echo " bench Run performance benchmarks"
	@echo ""
	@echo " Code Quality:"
	@echo " lint Run golangci-lint"
	@echo " vet Run go vet"
	@echo " fmt Format all Go code"
	@echo " security Run gosec + govulncheck"
	@echo ""
	@echo " Diagnostics:"
	@echo " doctor Check tool availability & system health"
	@echo " validate Validate config file"
	@echo " validate-framework Run deterministic validation lab and benchmarks"
	@echo ""
	@echo " Lifecycle:"
	@echo " setup Install system dependencies"
	@echo " install Build and install to $(INSTALL_PATH)"
	@echo " uninstall Remove from $(INSTALL_PATH)"
	@echo " clean Remove build artifacts"
	@echo ""
