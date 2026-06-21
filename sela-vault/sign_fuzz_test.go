package main

import (
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"testing"
)

// FuzzParsePSBTInput bombards the PSBT parser with random garbage to ensure it NEVER panics.
// This proves that a maliciously crafted QR code or file can never crash the vault.
func FuzzParsePSBTInput(f *testing.F) {
	// Add some valid-looking seeds
	f.Add([]byte("ur:crypto-psbt/"))
	f.Add([]byte("cHNidA=="))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		// We expect errors, but we MUST NOT panic.
		// If it panics, the fuzz test fails automatically.
		_, _ = parsePSBTInput(data)
	})
}

// FuzzDerivePath bombards the BIP32 derivation engine with random path indexes.
// This ensures that no combination of strange account numbers or change indexes
// can cause a "data-dependent" crash or mathematical panic.
func FuzzDerivePath(f *testing.F) {
	masterKey, err := hdkeychain.NewMaster([]byte("a very secure long string that acts as a mock seed"), &chaincfg.MainNetParams)
	if err != nil {
		f.Fatalf("failed to create master key: %v", err)
	}

	// Provide some initial seeds: typical BIP84 paths
	f.Add(uint32(84+hdkeychain.HardenedKeyStart), uint32(0+hdkeychain.HardenedKeyStart), uint32(0+hdkeychain.HardenedKeyStart), uint32(0), uint32(0))
	f.Add(uint32(84+hdkeychain.HardenedKeyStart), uint32(1+hdkeychain.HardenedKeyStart), uint32(2+hdkeychain.HardenedKeyStart), uint32(1), uint32(500))

	f.Fuzz(func(t *testing.T, p1, p2, p3, p4, p5 uint32) {
		path := []uint32{p1, p2, p3, p4, p5}
		// We expect it to either return a key or an error (e.g. invalid child index).
		// But it MUST NOT panic.
		key, err := derivePath(masterKey, path)
		if err == nil {
			key.Zero() // clean up memory
		}
	})
}
