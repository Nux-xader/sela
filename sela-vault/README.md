# sela-vault (The Guardian)

This is the **Vault & Address Derivation** component of the SELA project. It securely encrypts your BIP-39 mnemonic phrase and derives Native Segwit (BIP-84) Bitcoin addresses.

## What Does It Do?

`sela-vault` provides three main capabilities:
1.  **Initialize Vault (`init`)**: Accepts a 24-word mnemonic and encrypts it using Argon2id for key derivation and AES-256-GCM. The encrypted payload is saved locally as `vault.sela`.
2.  **Derive Address (`addr`)**: Loads the vault, decrypts the mnemonic in-memory, derives the BIP-84 Native Segwit address (`bc1q...` or `tb1q...`) at index 0, and immediately wipes all secrets from RAM.
3.  **Generate Pairing QR (`pair`)**: Generates an optimized, uppercase `UR:CRYPTO-ACCOUNT/...` representation of the account extended public key (XPUB) for pairing with wallets like Sparrow Wallet.

---

## Technical Specifications

### 1. Encryption & Storage (`vault.go`)
To protect against brute-force attacks on the vault file, we use heavy cryptographic parameters:
*   **Key Derivation Function**: Argon2id.
*   **Argon2id Parameters**: Time/Passes = 1, Memory = 512 MB (512 * 1024 KiB), Parallelism/Threads = 4.
*   **Salt Size**: 64 bytes (512 bits) of cryptographically secure random bytes (`crypto/rand`).
*   **Encryption Cipher**: AES-256-GCM (Authenticated Encryption) with a unique 12-byte random nonce per save.

### 2. Cryptographic Core (`bip` package)
Key derivation and elliptic curve operations are complex. To eliminate the risk of mathematical implementation bugs, `sela-vault` uses the industry-standard, audited Go packages from **`btcsuite`**:
*   **BIP-32 HD Derivation**: Handled via `github.com/btcsuite/btcd/btcutil/hdkeychain`.
*   **secp256k1 Curve Math**: Handled via `github.com/btcsuite/btcd/btcec/v2`.
*   **Bech32 Encoding**: Handled via `github.com/btcsuite/btcd/btcutil` (P2WPKH).
*   **BIP-39 Wordlist Validation & PBKDF2 Seed Derivation**: Handled via custom, audited implementation to keep mnemonic processing simple and transparent.

### 3. Active Memory Wiping
Sensitive variables (mnemonic bytes, passphrase bytes, vault passwords, intermediate keys, and derived seeds) are actively zeroed out (`WipeBytes`) in RAM immediately after use, both on success and failure (using Go's `defer` statement as a safety net).

---

## Usage

### 1. Encrypt and Save a Mnemonic (`init`)
Runs an interactive prompt to ask for a password (twice) and your 24-word mnemonic phrase:
```bash
go run . init
```
This generates the encrypted `vault.sela` file. **Keep this file offline.**

### 2. Derive Native Segwit Address (`addr`)
Prompts for your optional BIP-39 passphrase (25th word) and your vault password to output the corresponding Bech32 address at index 0 (supporting `--testnet` / `-testnet` flags):
```bash
go run . addr
# Or for testnet:
go run . --testnet addr
```
Outputs standard BIP-84 address:
```text
Derived BIP-84 Address (Index m/84'/0'/0'/0/0):
bc1qzmtrqsfuaf6l6kkcsseumq26ukaphfj9skkug6
```

### 3. Generate Pairing QR (`pair`)
Prompts for your optional BIP-39 passphrase (25th word) and your vault password, then outputs a `ur:crypto-account` QR code for pairing with software wallets like Sparrow Wallet (supporting `--testnet` / `-testnet` flags):
```bash
go run . pair
# Or for testnet:
go run . --testnet pair
```

---

## Development & Testing

Run unit tests to verify the correctness of the derivation logic against standard BIP-84 test vectors:
```bash
go test -v ./...
```

---

## Address Verification Security

Before sending any transactions, always verify your derived addresses. To protect against Address Poisoning and other errors, follow the **4-4-4 Verification Protocol** detailed in the [root README.md](../README.md#security-best-practices-address-verification).
