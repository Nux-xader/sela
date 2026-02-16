package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// --- CORE LOGIC ---

// loadWordlist reads the BIP-39 wordlist from a file and verifies its integrity
func loadWordlist(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Verify integrity using SHA256
	expectedHash := "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if fmt.Sprintf("%x", sha256.Sum256(content)) != expectedHash {
		return nil, fmt.Errorf("integrity check failed: wordlist modified")
	}

	// Simple parsing: strings.Fields handles newlines and spaces automatically
	words := strings.Fields(string(content))

	return words, nil
}

// generateEntropy generates cryptographically secure random bytes
func generateEntropy(bitSize int) ([]byte, error) {
	if bitSize%32 != 0 || bitSize < 128 || bitSize > 256 {
		return nil, fmt.Errorf("invalid entropy size: %d", bitSize)
	}
	bytes := make([]byte, bitSize/8)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// generateMnemonic creates a BIP-39 mnemonic from entropy
func generateMnemonic(entropy []byte, wordlist []string) (string, error) {
	entBits := len(entropy) * 8
	checksumBits := entBits / 32

	// Calculate SHA256 hash
	hash := sha256.Sum256(entropy)

	// We use a simple bit string approach for clarity and correctness
	// to avoid complex big.Int math that might be confusing to audit.
	var bits strings.Builder

	// 1. Convert Entropy to bits
	for _, b := range entropy {
		fmt.Fprintf(&bits, "%08b", b)
	}

	// 2. Append Checksum bits
	// Checksum is the first (ENT / 32) bits of the SHA256 hash.
	for i := range checksumBits {
		// Calculate which byte and bit index corresponds to the i-th bit
		byteIdx := i / 8
		bitIdx := 7 - (i % 8) // MSB first

		// Extract the bit
		if (hash[byteIdx]>>bitIdx)&1 == 1 {
			bits.WriteRune('1')
		} else {
			bits.WriteRune('0')
		}
	}

	allBits := bits.String()
	numWords := len(allBits) / 11
	var mnemonicWords []string

	// 3. Split into 11-bit chunks and map to words
	for i := range numWords {
		start := i * 11
		end := start + 11
		chunk := allBits[start:end]

		// Convert binary string chunk to integer index
		var index int64
		for _, c := range chunk {
			index = index << 1
			if c == '1' {
				index |= 1
			}
		}

		if index >= int64(len(wordlist)) {
			return "", fmt.Errorf("wordlist index out of range")
		}
		mnemonicWords = append(mnemonicWords, wordlist[index])
	}

	return strings.Join(mnemonicWords, " "), nil
}

// --- MAIN CLI ---

func main() {
	fmt.Println("--- SELA: Secure Encrypted Ledger Access ---")
	fmt.Println("Component: Key Generator (sela-gen)")
	fmt.Println("Security Level: MAXIMUM (256-bit Entropy / 24 Words)")
	fmt.Println("Using crypto/rand for CSPRNG")
	fmt.Println("-------------------------------------------")

	// Look for wordlist in current directory
	wordlist, err := loadWordlist("bip-39-english.txt")
	if err != nil {
		fmt.Printf("Error loading wordlist: %v\n", err)
		fmt.Println("Ensure 'bip-39-english.txt' is in the current directory.")
		os.Exit(1)
	}

	// Strict enforcement: Only 256-bit entropy (24 words)
	entropy256, err := generateEntropy(256)
	if err != nil {
		fmt.Printf("Error generating entropy: %v\n", err)
		os.Exit(1)
	}

	mnemonic24, err := generateMnemonic(entropy256, wordlist)
	if err != nil {
		fmt.Printf("Error generating mnemonic: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n[24 Words - 256-bit Entropy]")
	fmt.Println(mnemonic24)

	fmt.Println("\n-------------------------------------------")
	fmt.Println("KEEP THESE WORDS SAFE. DO NOT SHARE THEM OR COPY TO ONLINE DEVICE")
}
