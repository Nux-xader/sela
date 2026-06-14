package bip

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// LoadWordlist reads the BIP-39 wordlist and returns a list of words.
// This implementation is identical to sela-gen for consistency.
func LoadWordlist(filename string) ([]string, error) {
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
func ValidateMnemonic(mnemonicBytes []byte, wordMap map[string]int) error {
	// 1. ASCII Check (Secure against homoglyph attacks)
	for _, b := range mnemonicBytes {
		if b > 127 {
			return errors.New("mnemonic contains non-ASCII characters")
		}
	}

	words := bytes.Fields(mnemonicBytes)
	if len(words) != 24 {
		return fmt.Errorf("invalid length: expected 24 words, got %d", len(words))
	}

	// 2. Convert words to bits
	// Total bits = 24 words * 11 bits = 264 bits (33 bytes)
	buf := make([]byte, 33)
	defer WipeBytes(buf)

	for i, w := range words {
		// Compiler optimizes map lookups with string(byteSlice) to not allocate memory
		idx, ok := wordMap[string(w)]
		if !ok {
			return fmt.Errorf("word '%s' is not in the BIP-39 wordlist", string(w))
		}

		// Write 11 bits of idx starting at bit offset i * 11
		bitOffset := i * 11
		for j := range 11 {
			bit := (idx >> uint(10-j)) & 1
			pos := bitOffset + j
			byteIdx := pos / 8
			bitIdx := 7 - (pos % 8)
			if bit == 1 {
				buf[byteIdx] |= byte(1 << uint(bitIdx))
			}
		}
	}

	// 3. Calculate Expected Checksum (SHA256 of first 32 bytes / 256 bits of entropy)
	hash := sha256.Sum256(buf[:32])

	// 4. Verify Checksum (first 8 bits / 1 byte of SHA256 matches the 33rd byte)
	if hash[0] != buf[32] {
		return errors.New("checksum mismatch: mnemonic words are in wrong order or contain a typo")
	}

	return nil
}

// MnemonicToSeed derives the 64-byte seed from a mnemonic and passphrase utilizing PBKDF2-HMAC-SHA512 (2048 iterations)
func MnemonicToSeed(mnemonicBytes []byte, passphraseBytes []byte) []byte {
	salt := append([]byte("mnemonic"), passphraseBytes...)
	defer WipeBytes(salt)
	return pbkdf2.Key(mnemonicBytes, salt, 2048, 64, sha512.New)
}
