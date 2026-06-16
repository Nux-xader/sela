package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/Nux-xader/sela/sela-vault/util"
	"golang.org/x/crypto/argon2"
)

// Constants for crypto parameters
const (
	KDFTime        = 1          // Number of passes/iterations
	KDFMemory      = 512 * 1024 // 512 MB in KiB (maximum standard option)
	KDFThreads     = 4          // Parallelism (number of threads)
	SaltSize       = 64         // Increased to 64 bytes (512 bits) to match SHA-512 output & hedge against weak RNG
	NonceSize      = 12
	KeySize        = 32
	KDFAlgo        = "argon2id"
	CipherAlgo     = "aes-256-gcm"
	DefaultKeyFile = "vault.sela"
)

// Vault represents the encrypted storage format on disk.
type Vault struct {
	KDF struct {
		Algorithm   string `json:"algorithm"`
		Iterations  uint32 `json:"iterations"`  // Represents KDFTime for Argon2id
		Memory      uint32 `json:"memory"`      // Memory in KiB (Argon2id only)
		Parallelism uint8  `json:"parallelism"` // Parallelism (Argon2id only)
		Salt        []byte `json:"salt"`
	} `json:"kdf"`
	Cipher struct {
		Algorithm string `json:"algorithm"`
		Nonce     []byte `json:"nonce"`
		Data      []byte `json:"data"`
	} `json:"cipher"`
}

// EncryptMnemonic creates a new encrypted vault struct from a mnemonic and password.
// It performs heavy computation (Argon2id) to derive the encryption key.
func EncryptMnemonic(mnemonic []byte, password []byte) (*Vault, error) {
	// 1. Generate Random Salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, errors.New("failed to generate random salt: " + err.Error())
	}

	// 2. Derive Key from Password
	key := argon2.IDKey(password, salt, KDFTime, KDFMemory, KDFThreads, KeySize)
	defer util.WipeBytes(key)

	// 3. Initialize AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create aes cipher: " + err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to create gcm: " + err.Error())
	}

	// 4. Generate Random Nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("failed to generate random nonce: " + err.Error())
	}

	// 5. Encrypt (Seal)
	ciphertext := gcm.Seal(nil, nonce, mnemonic, nil)

	// 6. Construct Vault Struct
	v := &Vault{}
	v.KDF.Algorithm = KDFAlgo
	v.KDF.Iterations = KDFTime
	v.KDF.Memory = KDFMemory
	v.KDF.Parallelism = KDFThreads
	v.KDF.Salt = salt

	v.Cipher.Algorithm = CipherAlgo
	v.Cipher.Nonce = nonce
	v.Cipher.Data = ciphertext

	return v, nil
}

// Save writes the vault to the default file (sela.vault).
func (v *Vault) Save() error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(DefaultKeyFile, data, 0600)
}

// LoadVault loads the encrypted vault from the default file (sela.vault).
func LoadVault() (*Vault, error) {
	data, err := os.ReadFile(DefaultKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("vault file not found. Run 'sela-vault init' first.")
		}
		return nil, errors.New("failed to read vault file: " + err.Error())
	}

	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, errors.New("failed to unmarshal vault data: " + err.Error())
	}

	return &v, nil
}

// DecryptMnemonic decrypts the mnemonic from the vault using the provided password.
// It returns a byte slice so that the decrypted mnemonic can be securely zeroed out (wiped) in RAM when done.
func (v *Vault) DecryptMnemonic(password []byte) ([]byte, error) {
	// 1. Re-derive Key from Password
	key := argon2.IDKey(password, v.KDF.Salt, v.KDF.Iterations, v.KDF.Memory, v.KDF.Parallelism, KeySize)
	defer util.WipeBytes(key)

	// 2. Initialize AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create aes cipher for decryption: " + err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to create gcm for decryption: " + err.Error())
	}

	// 3. Decrypt (Open)
	// The original mnemonic was sealed with nil additional data, so we pass nil here too.
	plaintext, err := gcm.Open(nil, v.Cipher.Nonce, v.Cipher.Data, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt mnemonic. Incorrect password or corrupted vault: " + err.Error())
	}

	return plaintext, nil
}
