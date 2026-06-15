package main

import (
	"bytes"
	"testing"
)

func TestVaultEncryptDecryptArgon2id(t *testing.T) {
	mnemonic := []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	password := []byte("my-secure-password-123")

	// 1. Encrypt using Argon2id
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

	// 2. Decrypt
	decrypted, err := vault.DecryptMnemonic(password)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(mnemonic, decrypted) {
		t.Errorf("Decrypted mnemonic does not match original. Got: %s", string(decrypted))
	}

	// 3. Decrypt with wrong password
	_, err = vault.DecryptMnemonic([]byte("wrong-password"))
	if err == nil {
		t.Error("Expected decryption to fail with wrong password, but it succeeded")
	}
}
