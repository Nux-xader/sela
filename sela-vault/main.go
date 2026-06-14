package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Nux-xader/sela/sela-vault/bip"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "address":
		err = cmdAddress()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sela-vault <command>")
	fmt.Println("\nCommands:")
	fmt.Println("  init       Encrypt a mnemonic into sela.vault")
	fmt.Println("  address    Derive the Native Segwit BIP-84 address from the vault")
}

func cmdInit() error {
	// Safety Check: Prevent overwriting existing vault
	if _, err := os.Stat(DefaultKeyFile); err == nil {
		return fmt.Errorf("file '%s' already exists\nAborting to prevent overwriting your existing vault\nPlease move or rename the existing file if you really want to create a new one", DefaultKeyFile)
	}

	// 0. Load Wordlist first (Critical for validation)
	// We do this BEFORE asking for password to ensure system is ready.
	wordsList, err := bip.LoadWordlist("../bip-39-english.txt")
	if err != nil {
		return fmt.Errorf("loading wordlist: %w\nMake sure 'bip-39-english.txt' is in the parent directory", err)
	}

	// Create map for fast lookup and index retrieval
	wordMap := make(map[string]int)
	for i, w := range wordsList {
		wordMap[w] = i
	}

	fmt.Println("=== SELA VAULT INIT ===")

	// Get file descriptor for terminal input
	fd := int(os.Stdin.Fd())

	// 1. Read Password (FIRST - To minimize Time-in-Memory for Mnemonic)
	fmt.Print("Enter encryption password (hidden): ")
	passBytes, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("reading password: %w", err)
	}
	defer bip.WipeBytes(passBytes)
	fmt.Println()

	if len(passBytes) == 0 {
		return errors.New("password cannot be empty")
	}

	fmt.Print("Confirm password (hidden): ")
	confirmBytes, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("reading password confirmation: %w", err)
	}
	defer bip.WipeBytes(confirmBytes)
	fmt.Println()

	if !bytes.Equal(passBytes, confirmBytes) {
		return errors.New("passwords do not match")
	}

	// 2. Read Mnemonic (LAST step before encryption)
	fmt.Println("\nNow, enter your 24-word mnemonic phrase.")
	fmt.Print("Mnemonic: ")

	reader := bufio.NewReader(os.Stdin)
	inputBytes, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	defer bip.WipeBytes(inputBytes)

	mnemonicBytes := bytes.TrimSpace(inputBytes)

	// 3. Validation & Encryption (Immediate processing)
	fmt.Println("\nValidating Mnemonic (Checksum & Integrity)...")
	if err := bip.ValidateMnemonic(mnemonicBytes, wordMap); err != nil {
		return fmt.Errorf("invalid Mnemonic: %w", err)
	}

	// Encrypt immediately
	fmt.Println("Validation OK. Encrypting keys... (Please wait)")
	vault, err := EncryptMnemonic(mnemonicBytes, passBytes)
	if err != nil {
		return fmt.Errorf("initializing vault: %w", err)
	}

	// 4. Save
	if err := vault.Save(); err != nil {
		return fmt.Errorf("saving file: %w", err)
	}

	fmt.Printf("Success! Encrypted mnemonic saved to '%s'.\n", DefaultKeyFile)
	fmt.Println("Security depends on your password strength. Keep this file OFFLINE.")
	return nil
}

func cmdAddress() error {
	fmt.Println("=== SELA VAULT ADDRESS ===")

	// 1. Load Vault first (Fail-fast UX)
	vault, err := LoadVault()
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	// 2. Ask for wallet index (Visible)
	fmt.Print("Which wallet index? [Default: 0]: ")
	reader := bufio.NewReader(os.Stdin)
	indexStr, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading wallet index: %w", err)
	}
	indexStr = strings.TrimSpace(indexStr)
	var index uint32 = 0
	if indexStr != "" {
		_, err := fmt.Sscan(indexStr, &index)
		if err != nil {
			return fmt.Errorf("invalid wallet index '%s' (must be a non-negative integer)", indexStr)
		}
	}

	fd := int(os.Stdin.Fd())

	// 3. Ask for optional BIP-39 passphrase (Hidden)
	fmt.Print("Enter passphrase (25th word) [Hidden] [Optional]: ")
	passphraseBytes, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("reading passphrase: %w", err)
	}
	defer bip.WipeBytes(passphraseBytes)
	fmt.Println() // Newline

	// 4. Ask for vault password (Hidden)
	fmt.Print("Enter vault password (hidden): ")
	vaultPass, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("reading vault password: %w", err)
	}
	defer bip.WipeBytes(vaultPass)
	fmt.Println() // Newline

	if len(vaultPass) == 0 {
		return errors.New("vault password cannot be empty")
	}

	// 5. Decrypt Vault
	fmt.Println("\nDecrypting vault...")

	mnemonicBytes, err := vault.DecryptMnemonic(vaultPass)
	if err != nil {
		return fmt.Errorf("decrypting vault: %w", err)
	}
	defer bip.WipeBytes(mnemonicBytes)
	bip.WipeBytes(vaultPass) // Wipe vault password ASAP

	// 5. Generate address
	fmt.Println("Deriving keys and generating address...")
	address, err := bip.DeriveBIP84Address(mnemonicBytes, passphraseBytes, index)
	if err != nil {
		return fmt.Errorf("deriving address: %w", err)
	}

	// 6. Print Address
	fmt.Printf("\nDerived BIP-84 Address (Index %d/m/84'/0'/0'/0/%d):\n%s\n", index, index, address)
	if err := printQR(address); err != nil {
		fmt.Printf("Warning: Could not generate QR Code: %v\n", err)
	}
	return nil
}
