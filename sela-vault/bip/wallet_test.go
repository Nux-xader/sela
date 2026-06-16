package bip

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveBIP84Address(t *testing.T) {
	// Standard BIP-84 Test Vector
	// Mnemonic: 24 words of "abandon" ending in "art"
	mnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
	passphrase := []byte("")

	// Expected address from standard test vectors for path m/84'/0'/0'/0/0
	expectedAddr := "bc1qzmtrqsfuaf6l6kkcsseumq26ukaphfj9skkug6"

	addr, err := DeriveBIP84Address(mnemonic, passphrase, false)
	if err != nil {
		t.Fatalf("Failed to derive address: %v", err)
	}
	if addr != expectedAddr {
		t.Errorf("Address mismatch: got %s, want %s", addr, expectedAddr)
	}

	// Verify Testnet address starts with tb1q
	addrTestnet, err := DeriveBIP84Address(mnemonic, passphrase, true)
	if err != nil {
		t.Fatalf("Failed to derive Testnet address: %v", err)
	}
	if !strings.HasPrefix(addrTestnet, "tb1q") {
		t.Errorf("Expected Testnet address to start with tb1q, got %s", addrTestnet)
	}
}

func TestWipeBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	WipeBytes(b)
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
	defer WipeBytes(seed)

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
