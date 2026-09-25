package bip

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/Nux-xader/sela/sela-vault/util"
)

func TestDeriveBIP84Address(t *testing.T) {
	// Standard BIP-84 Test Vector
	// Mnemonic: 24 words of "abandon" ending in "art"
	mnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	passphrase := []byte("")

	// Expected address from standard test vectors for path m/84'/0'/0'/0/0
	expectedAddr := "bc1qzmtrqsfuaf6l6kkcsseumq26ukaphfj9skkug6"

	addr, err := DeriveBIP84Address(mnemonic, passphrase, false, 0)
	if err != nil {
		t.Fatalf("Failed to derive address: %v", err)
	}
	if addr != expectedAddr {
		t.Errorf("Address mismatch: got %s, want %s", addr, expectedAddr)
	}

	// Verify Testnet address starts with tb1q
	addrTestnet, err := DeriveBIP84Address(mnemonic, passphrase, true, 0)
	if err != nil {
		t.Fatalf("Failed to derive Testnet address: %v", err)
	}
	if !strings.HasPrefix(addrTestnet, "tb1q") {
		t.Errorf("Expected Testnet address to start with tb1q, got %s", addrTestnet)
	}
}

func TestWipeBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	util.WipeBytes(b)
	for i, val := range b {
		if val != 0 {
			t.Errorf("WipeBytes failed to zero index %d, got %v", i, val)
		}
	}
}

func TestMnemonicToSeed(t *testing.T) {
	mnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	passphrase := []byte("")

	seed := MnemonicToSeed(mnemonic, passphrase)
	defer util.WipeBytes(seed)

	if len(seed) != 64 {
		t.Errorf("Expected 64-byte seed, got %d bytes", len(seed))
	}

	// Seed for: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	// with passphrase "" is:
	// 408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840
	expectedHex := "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
	expectedBytes, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(seed, expectedBytes) {
		t.Logf("Got hex:  %x", seed)
		t.Logf("Want hex: %s", expectedHex)
		t.Errorf("MnemonicToSeed output does not match expected BIP-39 vector")
	}
}

func TestWipeBytesNil(t *testing.T) {
	// Ensure nil slice does not panic
	util.WipeBytes(nil)
}

func TestGenerateConfirmCode(t *testing.T) {
	code1 := util.GenerateConfirmCode()
	code2 := util.GenerateConfirmCode()

	if len(code1) != 5 {
		t.Errorf("Expected code length 5, got %d", len(code1))
	}
	const validCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	for _, ch := range code1 {
		if !strings.ContainsRune(validCharset, ch) {
			t.Errorf("Unexpected character in code: %c", ch)
		}
	}
	// Verify randomness (two codes should very likely not be identical)
	if code1 == code2 {
		t.Logf("Warning: code1 and code2 are identical (%s), check randomness if frequent", code1)
	}
}

func findWordlistPath() string {
	candidates := []string{
		"../bip-39-english.txt",
		"bip-39-english.txt",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func TestLoadWordlist(t *testing.T) {
	// 1. Non-existent file
	_, err := LoadWordlist("non_existent_wordlist.txt")
	if err == nil {
		t.Error("Expected error loading non-existent file, got nil")
	}

	// 2. Corrupted file (fails SHA256 integrity check)
	tmpFile := t.TempDir() + "/bad_wordlist.txt"
	if err := os.WriteFile(tmpFile, []byte("abandon ability able"), 0600); err != nil {
		t.Fatalf("Failed to create temp wordlist: %v", err)
	}
	_, err = LoadWordlist(tmpFile)
	if err == nil || !strings.Contains(err.Error(), "wordlist integrity failed") {
		t.Errorf("Expected wordlist integrity failed error, got: %v", err)
	}

	// 3. Valid wordlist if available in repo
	if validPath := findWordlistPath(); validPath != "" {
		words, err := LoadWordlist(validPath)
		if err != nil {
			t.Fatalf("Failed to load valid wordlist: %v", err)
		}
		if len(words) != 2048 {
			t.Errorf("Expected 2048 words, got %d", len(words))
		}
		if words[0] != "abandon" || words[2047] != "zoo" {
			t.Errorf("Unexpected boundary words: first=%q, last=%q", words[0], words[2047])
		}
	}
}

func TestValidateMnemonic(t *testing.T) {
	// Setup mock word map with subset or standard words
	wordMap := map[string]int{
		"abandon":  0,
		"ability":  1,
		"able":     2,
		"about":    3,
		"above":    4,
		"absent":   5,
		"absorb":   6,
		"abstract": 7,
		"absurd":   8,
		"abuse":    9,
		"access":   10,
		"accident": 11,
		"art":      99, // dummy index for testing
	}

	// 1. Non-ASCII check
	err := ValidateMnemonic([]byte("abandon abôut"), wordMap)
	if err == nil || !strings.Contains(err.Error(), "non-ASCII") {
		t.Errorf("Expected non-ASCII error, got: %v", err)
	}

	// 2. Invalid word count (not 24 words)
	err = ValidateMnemonic([]byte("abandon ability able"), wordMap)
	if err == nil || !strings.Contains(err.Error(), "expected 24 words") {
		t.Errorf("Expected 24 words length error, got: %v", err)
	}

	// 3. Word not in wordlist
	twentyFourWordsUnknown := strings.Repeat("abandon ", 23) + "unknownword"
	err = ValidateMnemonic([]byte(twentyFourWordsUnknown), wordMap)
	if err == nil || !strings.Contains(err.Error(), "not in the BIP-39 wordlist") {
		t.Errorf("Expected unknown word error, got: %v", err)
	}

	// 4. Checksum mismatch
	// 24 words of "abandon" will fail checksum because the 24th word requires a specific checksum byte
	twentyFourAbandons := strings.Repeat("abandon ", 23) + "abandon"
	err = ValidateMnemonic([]byte(twentyFourAbandons), wordMap)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("Expected checksum mismatch error, got: %v", err)
	}

	// 5. Valid 24-word mnemonic with correct checksum
	// Load full wordlist to test real valid BIP-39 mnemonic
	if validPath := findWordlistPath(); validPath != "" {
		words, err := LoadWordlist(validPath)
		if err != nil {
			t.Fatalf("Failed to load valid wordlist for mnemonic validation: %v", err)
		}
		fullWordMap := make(map[string]int, len(words))
		for idx, w := range words {
			fullWordMap[w] = idx
		}
		// Standard valid 24-word mnemonic: 23 "abandon" + "art"
		validMnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
		if err := ValidateMnemonic(validMnemonic, fullWordMap); err != nil {
			t.Errorf("Expected valid mnemonic to pass, got: %v", err)
		}
	}
}
