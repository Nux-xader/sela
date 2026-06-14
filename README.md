# SELA (Secure Encrypted Ledger Access)

**SELA** (Javanese: *Stone/Celah*) is an air-gapped crypto vault project designed for the paranoid.

## The Problem: Blind Trust
Modern software development is built on a mountain of trust. A simple "Hello World" app often pulls in hundreds of dependencies from unknown authors. For a crypto wallet holding your life savings, this "blind trust" is an unacceptable risk.

## The SELA Solution: Radical Isolation & Honest Security

SELA is not a monolithic application. It is a suite of two strictly isolated tools, each designed with a specific security philosophy to minimize the attack surface.

### 1. [sela-gen](./sela-gen) (The Creator)
*   **Purpose**: Generating your 24-word master secret (BIP-39).
*   **Philosophy**: **Zero External Dependencies**.
*   **Why**: The birth of your key is the most critical moment. We believe you should be able to audit 100% of the code that generates it. `sela-gen` uses **only** the Go Standard Library. No third-party code. No supply chain risks.

### 2. [sela-vault](./sela-vault) (The Guardian)
*   **Purpose**: Encrypting your mnemonic and deriving keys/addresses.
*   **Philosophy**: **Trusted Dependencies** (`btcsuite`).
*   **Why**: Key derivation (BIP-32) and elliptic curve operations (secp256k1) are mathematically complex and prone to implementation bugs. To prevent loss of funds, `sela-vault` uses the industry-standard, battle-tested `btcsuite` packages for cryptographic operations, while keeping a minimal, auditable wrapper for storage and CLI.

---

## Honest Security: Our Trust Hierarchy

We do not claim "Trust No One" because that is technically impossible. Instead, we offer a transparent **Trust Hierarchy** with options for the extremely paranoid.

1.  **Hardware**: We trust the CPU to execute instructions correctly.
2.  **Compiler**: We trust the official Go Toolchain.
3.  **OS Kernel**: Trusted for RNG in *Standard Mode*. **BYPASSED** in *Dice Mode*.
4.  **YOU**: We design the code so **you** can audit it.

**We DO NOT trust:**
*   NPM/Cargo/Go Module ecosystems (except vetted, standard blockchain libraries like `btcsuite`).
*   Random GitHub maintainers.
*   "Black box" compiled libraries.

## Architecture

SELA is a **Multi-Module Monorepo**. There is no shared root configuration. Each component is an island.

```text
sela/
├── sela-gen/       # Independent Module: Generates Keys (Zero Deps)
└── sela-vault/     # Independent Module: Stores Vault & Derives Keys (Trusted Deps)
```

## Getting Started

1. To generate a new master key (Phase 1):
   ```bash
   cd sela-gen
   go run main.go
   ```

2. To encrypt and store your mnemonic and derive addresses (Phase 2):
   ```bash
   cd sela-vault
   go run . init
   go run . address
   ```

---

## Security Best Practices: Address Verification

To prevent loss of funds, you must verify derived addresses before sending transactions.

### The Danger of Address Poisoning
Many users only check the last few characters of an address. Hackers exploit this habit via **Address Poisoning Attacks**. Using vanity address generators, attackers can easily generate a matching prefix (e.g., `bc1q...`) and suffix (e.g., `...kug6`) to match your legitimate address. They then send a zero-value transaction to your wallet so that the malicious address appears in your transaction history, hoping you will copy-paste it for your next transfer.

### The "4-4-4" Verification Protocol
To combat poisoning attacks and ensure transmission integrity, always verify your derived addresses using the **4-4-4 Rule**:
1. **First 4 Characters**: Verify the 4 characters immediately following the standard network prefix (e.g., for `bc1q[zmtr]...`, check `zmtr`).
2. **Middle 4 Characters**: Pick a random segment of 4 characters in the middle of the address (e.g., `...[csse]...`).
3. **Last 4 Characters**: Verify the final 4 characters of the address (e.g., `...[kug6]`).

### Why This Protocol Protects You
* **Cryptographic Spoofing Defense**: Generating a vanity address that matches the prefix, suffix, and a specific middle sequence of another address requires finding a collision across 12 specific characters. This is computationally infeasible in real-time.
* **Human-Error Prevention**: While inspecting 12 characters protects against spoofing, typos are handled automatically by the protocol.

> [!WARNING]
> **Bech32 Native Integrity Protection:**
> Bitcoin's Bech32 (BIP-173) address format includes a built-in BCH checksum. If even a single character is mistyped or corrupted during manual entry, copy-pasting, or QR scanning, compliant wallets and transaction builders will **automatically reject** the address as invalid. Funds cannot be broadcast to a corrupted Bech32 address. The 4-4-4 check is primarily to prevent sending to a *different, valid* address (poisoning) rather than detecting typos, which the protocol handles automatically.

