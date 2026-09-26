.PHONY: all build sela-vault sela-gen sela-vault-amd64 sela-vault-arm64 sela-gen-amd64 sela-gen-arm64 test clean help

LDFLAGS := -s -w

all: build

build: sela-vault sela-gen

## SELA VAULT TARGETS
sela-vault: sela-vault-amd64 sela-vault-arm64

sela-vault-amd64:
	@mkdir -p sela-vault/release
	@echo "Building sela-vault for linux/amd64 (no CGO)..."
	cd sela-vault && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o release/sela-vault-linux-amd64 .
	@cp bip-39-english.txt sela-vault/release/bip-39-english.txt

sela-vault-arm64:
	@mkdir -p sela-vault/release
	@echo "Building sela-vault for linux/arm64 (no CGO)..."
	cd sela-vault && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o release/sela-vault-linux-arm64 .
	@cp bip-39-english.txt sela-vault/release/bip-39-english.txt

## SELA GEN TARGETS
sela-gen: sela-gen-amd64 sela-gen-arm64

sela-gen-amd64:
	@mkdir -p sela-gen/release
	@echo "Building sela-gen for linux/amd64 (no CGO)..."
	cd sela-gen && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o release/sela-gen-linux-amd64 .
	@cp bip-39-english.txt sela-gen/release/bip-39-english.txt

sela-gen-arm64:
	@mkdir -p sela-gen/release
	@echo "Building sela-gen for linux/arm64 (no CGO)..."
	cd sela-gen && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o release/sela-gen-linux-arm64 .
	@cp bip-39-english.txt sela-gen/release/bip-39-english.txt

## TESTING
test:
	@echo "Running sela-vault tests..."
	cd sela-vault && go test -v ./...
	@echo "Running sela-gen tests..."
	cd sela-gen && go test -v ./...

## CLEANUP
clean:
	@echo "Cleaning release artifacts..."
	rm -rf sela-vault/release sela-gen/release
	rm -f sela-vault/sela-vault sela-gen/sela-gen

## HELP
help:
	@echo "SELA Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make               Build all binaries (amd64 & arm64) into respective release/ folders"
	@echo "  make sela-vault    Build sela-vault (amd64 & arm64) into sela-vault/release/"
	@echo "  make sela-gen      Build sela-gen (amd64 & arm64) into sela-gen/release/"
	@echo "  make test          Run unit tests across all modules"
	@echo "  make clean         Remove all release binaries"
