package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVaultEncryptDecryptArgon2id(t *testing.T) {
	mnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	password := []byte("my-secure-password-123")

	// Encrypt using Argon2id
	vault, err := EncryptMnemonic(mnemonic, password)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if vault.KDF.Algorithm != "argon2id" {
		t.Errorf("Expected KDF algorithm to be argon2id, got %s", vault.KDF.Algorithm)
	}
	if vault.KDF.Memory != KDFMemory {
		t.Errorf("Expected memory to be %d, got %d", KDFMemory, vault.KDF.Memory)
	}
	if vault.KDF.Iterations != KDFTime {
		t.Errorf("Expected iterations to be %d, got %d", KDFTime, vault.KDF.Iterations)
	}
	if vault.KDF.Parallelism != KDFThreads {
		t.Errorf("Expected parallelism to be %d, got %d", KDFThreads, vault.KDF.Parallelism)
	}

	// Decrypt
	decrypted, err := vault.DecryptMnemonic(password)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(mnemonic, decrypted) {
		t.Errorf("Decrypted mnemonic does not match original. Got: %s", string(decrypted))
	}

	// Decrypt with wrong password
	_, err = vault.DecryptMnemonic([]byte("wrong-password"))
	if err == nil {
		t.Error("Expected decryption to fail with wrong password, but it succeeded")
	}
}

func TestBuildCryptoAccountUR(t *testing.T) {
	masterFP := uint32(0x37b5eed4)
	pubKeyBytes := make([]byte, 33)
	pubKeyBytes[0] = 0x03
	chainCode := make([]byte, 32)
	parentFPBytes := []byte{0x0d, 0x5d, 0xfb, 0xd7}

	// Test Mainnet
	urMainnet := BuildCryptoAccountUR(masterFP, pubKeyBytes, chainCode, parentFPBytes, false)
	if !strings.HasPrefix(urMainnet, "ur:crypto-account/") {
		t.Errorf("Expected UR to start with ur:crypto-account/, got %s", urMainnet)
	}

	// Test Testnet
	urTestnet := BuildCryptoAccountUR(masterFP, pubKeyBytes, chainCode, parentFPBytes, true)
	if !strings.HasPrefix(urTestnet, "ur:crypto-account/") {
		t.Errorf("Expected UR to start with ur:crypto-account/, got %s", urTestnet)
	}
}
