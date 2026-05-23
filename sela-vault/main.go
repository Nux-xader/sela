package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sela-vault <command>")
	fmt.Println("\nCommands:")
	fmt.Println("  init    Encrypt a mnemonic into sela.vault")
}

func cmdInit() {
	// Safety Check: Prevent overwriting existing vault
	if _, err := os.Stat(DefaultKeyFile); err == nil {
		fmt.Printf("Error: File '%s' already exists.\n", DefaultKeyFile)
		fmt.Println("Aborting to prevent overwriting your existing vault.")
		fmt.Println("Please move or rename the existing file if you really want to create a new one.")
		os.Exit(1)
	}

	// 0. Load Wordlist first (Critical for validation)
	// We do this BEFORE asking for password to ensure system is ready.
	wordsList, err := loadWordlist("../bip-39-english.txt")
	if err != nil {
		fmt.Printf("Error loading wordlist: %v\n", err)
		fmt.Println("Make sure 'bip-39-english.txt' is in the parent directory.")
		os.Exit(1)
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
		fmt.Printf("\nError reading password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println() // Newline

	if len(passBytes) == 0 {
		fmt.Println("Error: Password cannot be empty.")
		os.Exit(1)
	}

	fmt.Print("Confirm password (hidden): ")
	confirmBytes, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Printf("\nError reading password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println() // Newline

	if !bytes.Equal(passBytes, confirmBytes) {
		fmt.Println("Error: Passwords do not match.")
		os.Exit(1)
	}

	// 2. Read Mnemonic (LAST step before encryption)
	fmt.Println("\nNow, enter your 24-word mnemonic phrase.")
	fmt.Print("Mnemonic: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}

	mnemonic := strings.TrimSpace(input)

	// 3. Validation & Encryption (Immediate processing)
	fmt.Println("\nValidating Mnemonic (Checksum & Integrity)...")
	if err := ValidateMnemonic(mnemonic, wordMap); err != nil {
		fmt.Printf("Error: Invalid Mnemonic: %v\n", err)
		os.Exit(1)
	}

	// Encrypt immediately
	fmt.Println("Validation OK. Encrypting keys... (Please wait)")
	vault, err := EncryptMnemonic(mnemonic, passBytes)
	if err != nil {
		fmt.Printf("Error initializing vault: %v\n", err)
		os.Exit(1)
	}

	// 4. Save
	if err := vault.Save(); err != nil {
		fmt.Printf("Error saving file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Success! Encrypted mnemonic saved to '%s'.\n", DefaultKeyFile)
	fmt.Println("Security depends on your password strength. Keep this file OFFLINE.")
}
