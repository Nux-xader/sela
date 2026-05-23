package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
)

// loadWordlist reads the BIP-39 wordlist and returns a list of words.
// This implementation is identical to sela-gen for consistency.
func loadWordlist(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	// Verify SHA256 integrity
	expected := "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if fmt.Sprintf("%x", sha256.Sum256(content)) != expected {
		return nil, fmt.Errorf("wordlist integrity failed")
	}
	return strings.Fields(string(content)), nil
}

// ValidateMnemonic checks if the mnemonic is valid according to BIP-39 rules.
// It verifies ASCII compliance, word existence, and CHECKSUM integrity.
func ValidateMnemonic(mnemonic string, wordMap map[string]int) error {
	// 1. ASCII Check (Secure against homoglyph attacks)
	for _, r := range mnemonic {
		if r > 127 {
			return errors.New("mnemonic contains non-ASCII characters")
		}
	}

	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		return fmt.Errorf("invalid length: expected 24 words, got %d", len(words))
	}

	// 2. Convert words to bits
	// Total bits = 24 words * 11 bits = 264 bits
	var bitsBuilder strings.Builder
	for _, w := range words {
		idx, ok := wordMap[w]
		if !ok {
			return fmt.Errorf("word '%s' is not in the BIP-39 wordlist", w)
		}
		// Append 11-bit binary representation of the index
		fmt.Fprintf(&bitsBuilder, "%011b", idx)
	}

	bits := bitsBuilder.String()
	if len(bits) != 264 {
		return errors.New("internal error: bit length mismatch")
	}

	// 3. Split into Entropy (256 bits) and Checksum (8 bits)
	entropyBits := bits[:256]
	checksumBits := bits[256:]

	// 4. Convert Entropy bits to Bytes
	entropy := make([]byte, 32)
	for i := range 32 {
		// Take 8 bits at a time
		byteStr := entropyBits[i*8 : (i+1)*8]
		var val byte
		for j := range 8 {
			if byteStr[j] == '1' {
				val |= 1 << (7 - j)
			}
		}
		entropy[i] = val
	}

	// 5. Calculate Expected Checksum
	// SHA256(Entropy) -> Take first 8 bits
	hash := sha256.Sum256(entropy)
	expectedByte := hash[0]
	expectedBits := fmt.Sprintf("%08b", expectedByte)

	// 6. Verify Checksum
	if checksumBits != expectedBits {
		return errors.New("checksum mismatch: mnemonic words are in wrong order or contain a typo")
	}

	return nil
}
