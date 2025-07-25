# CertForge Makefile

# Binary name
BINARY_NAME=certforge

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet

# Build settings
VERSION ?= v1.0.0
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Build directories
BUILD_DIR=./build
DIST_DIR=./dist

# Operating systems
PLATFORM_LINUX=linux
PLATFORM_MACOS=darwin
PLATFORM_WINDOWS=windows

# Architectures
ARCH_AMD64=amd64
ARCH_ARM64=arm64
ARCH_386=386

# Default target
.PHONY: all
all: clean build install

# Build for the current platform
.PHONY: build
build:
	@echo "Building CertForge..."
	$(GOBUILD) -o $(BINARY_NAME) $(LDFLAGS)
	chmod +x $(BINARY_NAME)
	@echo "Done! Binary is available at ./$(BINARY_NAME)"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Create build directories
.PHONY: mkdir
mkdir:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(DIST_DIR)

# Cross-compile for multiple platforms
.PHONY: build-all
build-all: mkdir build-linux build-macos build-windows

# Build for Linux
.PHONY: build-linux
build-linux:
	@echo "Building for Linux (amd64)..."
	GOOS=$(PLATFORM_LINUX) GOARCH=$(ARCH_AMD64) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(PLATFORM_LINUX)-$(ARCH_AMD64) $(LDFLAGS)
	@echo "Building for Linux (arm64)..."
	GOOS=$(PLATFORM_LINUX) GOARCH=$(ARCH_ARM64) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(PLATFORM_LINUX)-$(ARCH_ARM64) $(LDFLAGS)

# Build for MacOS
.PHONY: build-macos
build-macos:
	@echo "Building for MacOS (amd64)..."
	GOOS=$(PLATFORM_MACOS) GOARCH=$(ARCH_AMD64) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(PLATFORM_MACOS)-$(ARCH_AMD64) $(LDFLAGS)
	@echo "Building for MacOS (arm64)..."
	GOOS=$(PLATFORM_MACOS) GOARCH=$(ARCH_ARM64) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(PLATFORM_MACOS)-$(ARCH_ARM64) $(LDFLAGS)

# Build for Windows
.PHONY: build-windows
build-windows:
	@echo "Building for Windows (amd64)..."
	GOOS=$(PLATFORM_WINDOWS) GOARCH=$(ARCH_AMD64) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(PLATFORM_WINDOWS)-$(ARCH_AMD64).exe $(LDFLAGS)
	@echo "Building for Windows (386)..."
	GOOS=$(PLATFORM_WINDOWS) GOARCH=$(ARCH_386) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(PLATFORM_WINDOWS)-$(ARCH_386).exe $(LDFLAGS)

# Create distribution packages
.PHONY: dist
dist: build-all
	@echo "Creating distribution packages..."
	cd $(BUILD_DIR) && tar -czvf ../$(DIST_DIR)/$(BINARY_NAME)-$(PLATFORM_LINUX)-$(ARCH_AMD64).tar.gz $(BINARY_NAME)-$(PLATFORM_LINUX)-$(ARCH_AMD64)
	cd $(BUILD_DIR) && tar -czvf ../$(DIST_DIR)/$(BINARY_NAME)-$(PLATFORM_LINUX)-$(ARCH_ARM64).tar.gz $(BINARY_NAME)-$(PLATFORM_LINUX)-$(ARCH_ARM64)
	cd $(BUILD_DIR) && tar -czvf ../$(DIST_DIR)/$(BINARY_NAME)-$(PLATFORM_MACOS)-$(ARCH_AMD64).tar.gz $(BINARY_NAME)-$(PLATFORM_MACOS)-$(ARCH_AMD64)
	cd $(BUILD_DIR) && tar -czvf ../$(DIST_DIR)/$(BINARY_NAME)-$(PLATFORM_MACOS)-$(ARCH_ARM64).tar.gz $(BINARY_NAME)-$(PLATFORM_MACOS)-$(ARCH_ARM64)
	cd $(BUILD_DIR) && zip -r ../$(DIST_DIR)/$(BINARY_NAME)-$(PLATFORM_WINDOWS)-$(ARCH_AMD64).zip $(BINARY_NAME)-$(PLATFORM_WINDOWS)-$(ARCH_AMD64).exe
	cd $(BUILD_DIR) && zip -r ../$(DIST_DIR)/$(BINARY_NAME)-$(PLATFORM_WINDOWS)-$(ARCH_386).zip $(BINARY_NAME)-$(PLATFORM_WINDOWS)-$(ARCH_386).exe
	@echo "Distribution packages created in $(DIST_DIR)"

# Install the binary
.PHONY: install
install:
	@echo "Installing CertForge..."
	@if [ -w /usr/local/bin ]; then \
		cp $(BINARY_NAME) /usr/local/bin/ && \
		chmod +x /usr/local/bin/$(BINARY_NAME) && \
		echo "Installed to /usr/local/bin/$(BINARY_NAME)"; \
	else \
		sudo cp $(BINARY_NAME) /usr/local/bin/ && \
		sudo chmod +x /usr/local/bin/$(BINARY_NAME) && \
		echo "Installed to /usr/local/bin/$(BINARY_NAME) (using sudo)"; \
	fi

# Show help
.PHONY: help
help:
	@echo "CertForge Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make              Build and install the binary (default)"
	@echo "  make build        Build the binary for the current platform"
	@echo "  make VERSION=v1.1.0 build   Build with specific version"
	@echo "  make clean        Remove build artifacts"
	@echo "  make test         Run tests"
	@echo "  make build-all    Build for multiple platforms (Linux, MacOS, Windows)"
	@echo "  make build-linux  Build for Linux (amd64, arm64)"
	@echo "  make build-macos  Build for MacOS (amd64, arm64)"
	@echo "  make build-windows Build for Windows (amd64, 386)"
	@echo "  make dist         Create distribution packages"
	@echo "  make install      Install the binary to /usr/local/bin"
	@echo "  make help         Show this help"

.DEFAULT_GOAL := all
