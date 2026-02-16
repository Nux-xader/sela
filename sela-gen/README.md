# sela-gen (SELA Generator)

This is the **Key Generator** component of the SELA project.

## What Does It Do?

`sela-gen` creates a cryptographically secure **24-word Mnemonic Phrase** (also known as a Seed Phrase).

This is not just a random list of words. It is a precise mathematical representation of a **256-bit entropy** master key, generated according to the **BIP-39 standard** (Bitcoin Improvement Proposal 39).

### Technical Specifications
*   **Entropy**:
    *   **Standard Mode**: 256 bits (32 bytes) from OS CSPRNG (`crypto/rand`).
    *   **Paranoid Mode**: >256 bits derived from **physical universe entropy** (dice rolls), whitened via SHA-256.
*   **Checksum**: SHA256 (first 8 bits). Acts as a built-in error detection code for the 24 words (prevents typos).
*   **Format**: 24 English words (BIP-39).

---

## The Goal: Radical Auditability

The specific purpose of this tool is to generate your master secret (24 words) in an environment where **you** can verify every single line of code that runs.

## Philosophy

### 1. Complexity is the Enemy of Security
Complex code is the natural habitat of bugs. We believe **simplicity is a security feature**.

*   **Minimal Surface Area**: Logic contained in a single file.
*   **No Abstractions**: Clear, linear logic.
*   **Human Verifiable**: Auditable in minutes.

### 2. Honest Security & Optional Paranoia

We prefer to be honest about our **Trust Hierarchy**:

#### Level 1: Standard Mode (Default)
*   **Trusts**: Hardware CPU, OS Kernel (for RNG), Go Compiler.
*   **Use Case**: Secure enough for 99.9% of users.

#### Level 2: Paranoid Mode (Dice Rolls)
*   **Trusts**: Hardware CPU (to calculate hash), Go Compiler.
*   **ELIMINATES**: Trust in the OS Random Number Generator.
*   **Entropy Source**: **The Universe itself**.
    *   By rolling dice, you are capturing true physical entropy (chaos, gravity, friction) that no algorithm or backdoor can predict.
    *   You are not relying on silicon to "simulate" randomness; you are feeding it raw chaos from the real world.
*   **The Math**:
    *   A 6-sided die provides $\log_2(6) \approx 2.58$ bits of entropy per roll.
    *   100 rolls $\times$ 2.58 bits $\approx$ 258 bits of entropy.
    *   We hash these rolls with SHA-256 to produce a perfectly uniform 256-bit key.

### 3. The Eliminated Trust (The SELA Advantage)
We **refuse** to trust the chaotic ecosystem of third-party libraries:
*   **Zero Dependencies**: No `npm`, `cargo`, or external Go modules.
*   **No Supply Chain Risk**.

## Usage

### Interactive Mode (Recommended)
Simply run the program and follow the prompts. You can choose between System RNG and Dice Rolls.

```bash
go run main.go
```

### Dice Mode Instructions
1. Select option `2` in the menu.
2. Roll a physical 6-sided die.
3. Type the number showing (1-6).
4. Repeat at least 100 times.
5. The tool will hash your inputs to generate the final key.
