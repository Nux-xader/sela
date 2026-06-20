# sela-vault (The Guardian)

This is the **Vault & Address Derivation** component of the SELA project. It securely encrypts your BIP-39 mnemonic phrase and derives Native Segwit (BIP-84) Bitcoin addresses.

## What Does It Do?

`sela-vault` provides four main capabilities:
1.  **Initialize Vault (`init`)**: Accepts a 24-word mnemonic and encrypts it using Argon2id for key derivation and AES-256-GCM. The encrypted payload is saved locally as `vault.sela`.
2.  **Derive Address (`addr`)**: Loads the vault, decrypts the mnemonic in-memory, derives the BIP-84 Native Segwit address (`bc1q...` or `tb1q...`) at index 0, and immediately wipes all secrets from RAM.
3.  **Generate Pairing QR (`pair`)**: Generates an optimized, uppercase `UR:CRYPTO-ACCOUNT/...` representation of the account extended public key (XPUB) for pairing with wallets like Sparrow Wallet.
4.  **Sign Transactions (`sign`)**: Accepts an unsigned PSBT (via Base64 or UR QR code), performs strict security validations (like Fake Change Address Protection), securely signs the transaction in a fully stateless manner, and outputs the signed PSBT for broadcast.

---

## Technical Specifications

### 1. Encryption & Storage (`vault.go`)
To protect against brute-force attacks on the vault file, we use heavy cryptographic parameters:
*   **Key Derivation Function**: Argon2id.
*   **Argon2id Parameters**: Time/Passes = 1, Memory = 512 MB (512 * 1024 KiB), Parallelism/Threads = 4.
*   **Salt Size**: 64 bytes (512 bits) of cryptographically secure random bytes (`crypto/rand`).
*   **Encryption Cipher**: AES-256-GCM (Authenticated Encryption) with a unique 12-byte random nonce per save.

### 2. Cryptographic Core (`bip` package & `sign.go`)
Key derivation, transaction parsing, and elliptic curve operations are complex. To eliminate the risk of mathematical implementation bugs, `sela-vault` uses the industry-standard, audited Go packages from **`btcsuite`**:
*   **BIP-32 HD Derivation**: Handled via `github.com/btcsuite/btcd/btcutil/hdkeychain`.
*   **secp256k1 Curve Math**: Handled via `github.com/btcsuite/btcd/btcec/v2`.
*   **Bech32 Encoding**: Handled via `github.com/btcsuite/btcd/btcutil`.
*   **PSBT/BIP-174 Parsing & Signing**: Handled via `github.com/btcsuite/btcd/btcutil/psbt` and `txscript`.
*   **BIP-39 Wordlist Validation**: Handled via custom, audited implementation to keep mnemonic processing simple.

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

### 4. Sign Transaction (`sign`)
Prompts for your optional BIP-39 passphrase, your vault password, and the Unsigned PSBT (either as a Base64 string or a `ur:crypto-psbt/...` payload from a camera scan). It then performs intense security validations before signing the transaction and outputting the Signed PSBT:
```bash
go run . sign
# Or for testnet:
go run . --testnet sign
```

---

## Development, Security & Testing

The `sela-vault` codebase relies on a **3-Layer Security Testing Pyramid** to ensure absolute cryptographic soundness:

1. **Standard Unit Testing (`vault_test.go`)**
   Tests deterministic business logic and explicit attack vectors.
   *Example: Hardcoded "Fake Change Address" attacks to ensure the signer actively blocks poisoned outputs.*
   ```bash
   go test -v ./...
   ```

2. **Native Fuzz Testing (`sign_fuzz_test.go`)**
   Bombards the PSBT parser and BIP32 derivation engine with millions of randomized, malformed, and out-of-bounds byte streams.
   *Goal: Ensures the vault can NEVER crash or panic from a maliciously crafted QR code (Zero Data-Dependent Bugs).*
   ```bash
   go test -fuzz=FuzzParsePSBTInput -fuzztime=30s
   go test -fuzz=FuzzDerivePath -fuzztime=30s
   ```

3. **End-to-End Regtest Battle Testing (`battle_test.go`)**
   A maximum-intensity integration test that dynamically scales to your machine's CPU cores (or uses `SELA_WORKERS`). It connects to a local Bitcoin Core `bitcoind` Regtest node via JSON-RPC. It randomly generates mnemonics, funds them from the Bitcoin Core faucet, builds random PSBTs, attacks 75% of them (Sighash, Fake Change, Ownership hijacks), signs them with Sela Vault, and broadcasts them back to Bitcoin Core.
   *Goal: Ensures 100% real-world consensus compatibility and perfect attack mitigation under chaotic conditions.*

   #### ⚠️ Clean Regtest Lifecycle (Crucial Before Every Run)
   Running tests repeatedly without resetting the blockchain database can cause transaction collisions, lock mature UTXO pools, and deplete the faucet. Always reset your regtest node configuration beforehand using these steps:

   1. **Stop any running Bitcoin daemon cleanly:**
      ```bash
      bitcoin-cli -regtest stop
      ```
   2. **Purge the regtest data directory to guarantee a clean slate (from genesis):**
      ```bash
      # Default Linux path (adjust if using a custom -datadir)
      rm -rf ~/.bitcoin/regtest
      ```
   3. **Restart the bitcoind daemon in Regtest mode:**
      ```bash
      bitcoind -regtest -daemon
      ```
   4. **Execute the Battle Test suite:**
      ```bash
      # Standard run (default 1000 transactions depth)
      BTC_RPC_USER=admin BTC_RPC_PASS=pass go test -v -tags=integration -run=TestRegtestBattle

      # Deep battle test (e.g., 20000 transactions across 8 CPU threads)
      SELA_BATTLE_DEPTH=20000 SELA_WORKERS=8 BTC_RPC_USER=admin BTC_RPC_PASS=pass go test -timeout 0 -v -tags=integration -run=TestRegtestBattle
      ```

---

## Address Verification Security

Before sending any transactions, always verify your derived addresses. To protect against Address Poisoning and other errors, follow the **4-4-4 Verification Protocol** detailed in the [root README.md](../README.md#security-best-practices-address-verification).
