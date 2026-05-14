BINARY_NAME=bbpts
CMD_PATH=./cmd/bbpts
SETUP_PATH=./cmd/setup
INSTALL_PATH=/usr/local/bin

# Detect OS for binary extension
ifeq ($(OS),Windows_NT)
    BINARY_EXT=.exe
else
    BINARY_EXT=
endif

.PHONY: all build test clean install uninstall help setup

all: build

setup:
	@echo "Running cross-platform setup..."
	bash scripts/setup.sh

build:
	@echo "Building $(BINARY_NAME)$(BINARY_EXT)..."
	go build -o $(BINARY_NAME)$(BINARY_EXT) $(CMD_PATH)

test:
	@echo "Running tests..."
	go test -v ./...

doctor: build
	@echo "Running environment diagnostics..."
	./$(BINARY_NAME)$(BINARY_EXT) -doctor

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)$(BINARY_EXT)
	go clean

install: build
ifeq ($(OS),Windows_NT)
	@echo "Install target not fully supported on Windows via Makefile. Please copy $(BINARY_NAME).exe to your PATH."
else
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	sudo cp $(BINARY_NAME) $(INSTALL_PATH)
endif

uninstall:
ifeq ($(OS),Windows_NT)
	@echo "Uninstall target not supported on Windows via Makefile."
else
	@echo "Removing $(BINARY_NAME) from $(INSTALL_PATH)..."
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
endif

help:
	@echo "BBPTS Makefile targets:"
	@echo "  setup     - Run cross-platform setup (installs deps and tools)"
	@echo "  build     - Build the binary"
	@echo "  test      - Run all tests"
	@echo "  clean     - Remove built binary and clean Go cache"
	@echo "  install   - Build and install binary (Linux/macOS)"
	@echo "  uninstall - Remove binary (Linux/macOS)"
	@echo "  help      - Show this help message"
