BINARY_NAME=bbpts
CMD_PATH=./cmd/bbpts
INSTALL_PATH=/usr/local/bin
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Detect OS for binary extension
ifeq ($(OS),Windows_NT)
    BINARY_EXT=.exe
else
    BINARY_EXT=
endif

.PHONY: all build build-release test test-short test-race bench lint vet fmt \
        security doctor validate clean install uninstall setup help \
        coverage docker

all: build

# ─────────────────────────────────────────
# Build Targets
# ─────────────────────────────────────────

build:
	@echo "⚙️  Building $(BINARY_NAME)$(BINARY_EXT)..."
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)$(BINARY_EXT) $(CMD_PATH)
	@echo "✅ Build complete: ./$(BINARY_NAME)$(BINARY_EXT)"

build-release:
	@echo "📦 Building release binary with optimizations..."
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o $(BINARY_NAME)$(BINARY_EXT) $(CMD_PATH)

# ─────────────────────────────────────────
# Test Targets
# ─────────────────────────────────────────

test:
	@echo "🧪 Running all tests..."
	go test -v -count=1 ./...

test-short:
	@echo "🧪 Running short tests..."
	go test -short ./...

test-race:
	@echo "🧪 Running tests with race detector..."
	go test -v -race -count=1 ./...

coverage:
	@echo "📊 Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report: coverage.html"

bench:
	@echo "⏱️  Running benchmarks..."
	go test -bench=. -benchmem -run=^$$ ./... | tee benchmark.txt
	@echo "✅ Benchmark results: benchmark.txt"

# ─────────────────────────────────────────
# Code Quality
# ─────────────────────────────────────────

lint:
	@echo "🔍 Running linter..."
	golangci-lint run --timeout=5m ./...

vet:
	@echo "🔍 Running go vet..."
	go vet ./...

fmt:
	@echo "📝 Formatting code..."
	gofmt -s -w .
	@echo "✅ Code formatted"

security:
	@echo "🛡️  Running security scan..."
	@which gosec > /dev/null 2>&1 || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -fmt=json -out=gosec-report.json ./... || true
	@echo "✅ Security report: gosec-report.json"
	@echo "🔎 Running govulncheck..."
	@which govulncheck > /dev/null 2>&1 || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./... || true

# ─────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────

doctor: build
	@echo "🩺 Running environment diagnostics..."
	./$(BINARY_NAME)$(BINARY_EXT) -doctor

validate: build
	@echo "✅ Validating configuration..."
	./$(BINARY_NAME)$(BINARY_EXT) -validate-config

# ─────────────────────────────────────────
# Setup & Install
# ─────────────────────────────────────────

setup:
	@echo "🔧 Running cross-platform setup..."
	bash scripts/setup.sh

install: build
ifeq ($(OS),Windows_NT)
	@echo "Install target not fully supported on Windows via Makefile. Please copy $(BINARY_NAME).exe to your PATH."
else
	@echo "📦 Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	sudo cp $(BINARY_NAME) $(INSTALL_PATH)
	@echo "✅ Installed"
endif

uninstall:
ifeq ($(OS),Windows_NT)
	@echo "Uninstall target not supported on Windows via Makefile."
else
	@echo "🗑️  Removing $(BINARY_NAME) from $(INSTALL_PATH)..."
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
endif

# ─────────────────────────────────────────
# Docker
# ─────────────────────────────────────────

docker:
	@echo "🐳 Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .
	@echo "✅ Docker image built: $(BINARY_NAME):$(VERSION)"

# ─────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────

clean:
	@echo "🧹 Cleaning up..."
	rm -f $(BINARY_NAME)$(BINARY_EXT) coverage.out coverage.html benchmark.txt gosec-report.json
	go clean
	@echo "✅ Clean"

# ─────────────────────────────────────────
# Help
# ─────────────────────────────────────────

help:
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║           BBPTS Makefile Targets             ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
	@echo "  Build:"
	@echo "    build          Build the binary (debug)"
	@echo "    build-release  Build optimized release binary"
	@echo "    docker         Build Docker image"
	@echo ""
	@echo "  Test:"
	@echo "    test           Run all tests with verbose output"
	@echo "    test-short     Run short tests only"
	@echo "    test-race      Run tests with race detector"
	@echo "    coverage       Generate HTML coverage report"
	@echo "    bench          Run performance benchmarks"
	@echo ""
	@echo "  Code Quality:"
	@echo "    lint           Run golangci-lint"
	@echo "    vet            Run go vet"
	@echo "    fmt            Format all Go code"
	@echo "    security       Run gosec + govulncheck"
	@echo ""
	@echo "  Diagnostics:"
	@echo "    doctor         Check tool availability & system health"
	@echo "    validate       Validate config file"
	@echo ""
	@echo "  Lifecycle:"
	@echo "    setup          Install system dependencies"
	@echo "    install        Build and install to $(INSTALL_PATH)"
	@echo "    uninstall      Remove from $(INSTALL_PATH)"
	@echo "    clean          Remove build artifacts"
	@echo ""
