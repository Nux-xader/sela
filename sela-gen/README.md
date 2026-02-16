# sela-gen (SELA Generator)

This is the **Key Generator** component of the SELA project.

## What Does It Do?

`sela-gen` creates a cryptographically secure **24-word Mnemonic Phrase** (also known as a Seed Phrase).

This is not just a random list of words. It is a precise mathematical representation of a **256-bit entropy** master key, generated according to the **BIP-39 standard** (Bitcoin Improvement Proposal 39).

### Technical Specifications
*   **Entropy**: 256 bits (32 bytes) of pure random data from the OS kernel.
*   **Checksum**: SHA256 (first 8 bits) to detect typos during backup/restore.
*   **Format**: 24 English words from the standard BIP-39 wordlist.
*   **Compatibility**: The resulting phrase is compatible with major hardware wallets (Ledger, Trezor) and software wallets (Trust Wallet, Metamask, Electrum).

---

## The Goal: Radical Auditability

The specific purpose of this tool is to generate your master secret (24 words) in an environment where **you** can verify every single line of code that runs.

In modern software, trust is often hidden behind thousands of dependencies. `sela-gen` removes those hiding places.

## Philosophy

### 1. Complexity is the Enemy of Security
Complex code is the natural habitat of bugs and vulnerabilities. We believe that **simplicity is a security feature**.

*   **Minimal Surface Area**: Every line of code is a potential liability. We keep the codebase as small as possible.
*   **No Abstractions**: We avoid "clever" code. We prefer clear, obvious logic over obscure abstractions.
*   **Human Verifiable**: If you can't read it and understand it in one sitting, you shouldn't trust it with your life savings.

### 2. Honest Security
Security marketing often claims "Trust No One". This is technically false. Unless you fabricate your own silicon and write your own operating system, you are always trusting *someone*.

We prefer to be honest about our **Trust Hierarchy**:

### 1. The Unavoidable Trust (The Base)
We *must* trust these layers to function:
*   **Hardware**: The CPU (Intel/AMD/ARM) executing the instructions.
*   **OS**: The Kernel (Linux/Windows/macOS) providing entropy to the RNG.
*   **Compiler & StdLib**: The official Go Toolchain. We trust `crypto/rand` and `crypto/sha256` because they are the battle-tested standard, maintained by the Go Team (Google) and scrutinized by the global security community.

### 2. The Eliminated Trust (The SELA Advantage)
We **refuse** to trust the chaotic ecosystem of third-party libraries:
*   **No External Packages**: We use **Zero Dependencies**. No `npm install`, no `cargo build`, no fetching code from unknown GitHub repositories.
*   **No Supply Chain Risk**: You don't have to worry about a "left-pad" incident or a malicious maintainer injecting a backdoor in a sub-dependency.
*   **No "Black Boxes"**: The code is simple. There is no complex math library to audit—just standard function calls.

## Why This Matters

By stripping away everything non-essential, we achieve:

1.  **5-Minute Audit**: The entire logic fits in a single file (`main.go`). A human can read it, understand it, and verify it in minutes.
2.  **True Air-Gap**: Since there are no dependencies to download, this folder is self-contained. You can copy it to a strictly offline computer via USB and compile/run it with confidence.

## Usage

```bash
go run main.go
```
