.PHONY: all build prepare sela-vault sela-gen sela-vault-amd64 sela-vault-arm64 sela-gen-amd64 sela-gen-arm64 test clean help

LDFLAGS := -s -w
RELEASE_DIR := $(CURDIR)/release

all: build

build: prepare sela-vault sela-gen

prepare:
	@mkdir -p $(RELEASE_DIR)
	@cp bip-39-english.txt $(RELEASE_DIR)/bip-39-english.txt

## SELA VAULT TARGETS
sela-vault: sela-vault-amd64 sela-vault-arm64

sela-vault-amd64: prepare
	@echo "Building sela-vault for linux/amd64 (no CGO)..."
	cd sela-vault && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_DIR)/sela-vault-linux-amd64 .

sela-vault-arm64: prepare
	@echo "Building sela-vault for linux/arm64 (no CGO)..."
	cd sela-vault && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_DIR)/sela-vault-linux-arm64 .

## SELA GEN TARGETS
sela-gen: sela-gen-amd64 sela-gen-arm64

sela-gen-amd64: prepare
	@echo "Building sela-gen for linux/amd64 (no CGO)..."
	cd sela-gen && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_DIR)/sela-gen-linux-amd64 .

sela-gen-arm64: prepare
	@echo "Building sela-gen for linux/arm64 (no CGO)..."
	cd sela-gen && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_DIR)/sela-gen-linux-arm64 .

## TESTING
test:
	@echo "Running sela-vault tests..."
	cd sela-vault && go test -v ./...
	@echo "Running sela-gen tests..."
	cd sela-gen && go test -v ./...

## CLEANUP
clean:
	@echo "Cleaning release artifacts..."
	rm -rf $(RELEASE_DIR)

## HELP
help:
	@echo "SELA Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make               Build all binaries (amd64 & arm64) into the root release/ folder"
	@echo "  make sela-vault    Build sela-vault (amd64 & arm64) into release/"
	@echo "  make sela-gen      Build sela-gen (amd64 & arm64) into release/"
	@echo "  make test          Run unit tests across all modules"
	@echo "  make clean         Remove release artifacts"
