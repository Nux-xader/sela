package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Nux-xader/sela/sela-vault/bip"
	"golang.org/x/term"
)

func main() {
	flag.Usage = printUsage
	testnetPtr := flag.Bool("testnet", false, "Use Bitcoin Testnet")
	accountPtr := flag.Uint("account", 0, "Specify BIP-44/84 account index")
	flag.Parse()

	isTestnet := *testnetPtr
	accountIdx := uint32(*accountPtr)
	cmdArgs := flag.Args()

	if len(cmdArgs) < 1 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch cmdArgs[0] {
	case "init":
		err = cmdInit()
	case "addr":
		err = cmdAddr(isTestnet, accountIdx)
	case "pair":
		err = cmdPair(isTestnet, accountIdx)
	default:
		fmt.Printf("Unknown command: %s\n", cmdArgs[0])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sela-vault [flags] <command>")
	fmt.Println("\nFlags:")
	fmt.Println("  --testnet          Use Bitcoin Testnet (derives testnet keys and addresses)")
	fmt.Println("  --account <index>  Specify BIP-44/84 account index (default: 0)")
	fmt.Println("\nCommands:")
	fmt.Println("  init               Encrypt a mnemonic into sela.vault")
	fmt.Println("  addr               Derive the Native Segwit BIP-84 address from the vault")
	fmt.Println("  pair               Generate a ur:crypto-account QR code for Sparrow pairing")
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

	// Instantly clear the screen and scrollback buffer to hide cleartext mnemonic
	fmt.Print("\033[H\033[2J\033[3J")

	// Reprint clean vault init context
	fmt.Println("=== SELA VAULT INIT ===")
	fmt.Println("Mnemonic: [HIDDEN FOR SECURITY]")

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

func cmdAddr(isTestnet bool, accountIdx uint32) error {
	fmt.Println("=== SELA VAULT ADDRESS ===")

	// Load Vault first (Fail-fast UX)
	vault, err := LoadVault()
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	fd := int(os.Stdin.Fd())

	// Ask for optional BIP-39 passphrase (Hidden)
	fmt.Print("Enter passphrase (25th word) [Hidden] [Optional]: ")
	passphraseBytes, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("reading passphrase: %w", err)
	}
	defer bip.WipeBytes(passphraseBytes)
	fmt.Println() // Newline

	// Ask for vault password (Hidden)
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

	// Decrypt Vault
	fmt.Println("\nDecrypting vault...")

	mnemonicBytes, err := vault.DecryptMnemonic(vaultPass)
	if err != nil {
		return fmt.Errorf("decrypting vault: %w", err)
	}
	defer bip.WipeBytes(mnemonicBytes)
	bip.WipeBytes(vaultPass) // Wipe vault password ASAP

	// Generate address
	fmt.Println("Deriving keys and generating address...")
	address, err := bip.DeriveBIP84Address(mnemonicBytes, passphraseBytes, isTestnet, accountIdx)
	bip.WipeBytes(mnemonicBytes)   // Wipe mnemonic immediately after derivation
	bip.WipeBytes(passphraseBytes) // Wipe passphrase immediately after derivation
	if err != nil {
		return fmt.Errorf("deriving address: %w", err)
	}

	// Print Address
	pathStr := fmt.Sprintf("m/84'/0'/%d'/0/0", accountIdx)
	if isTestnet {
		pathStr = fmt.Sprintf("m/84'/1'/%d'/0/0", accountIdx)
	}
	fmt.Printf("\nDerived BIP-84 Address (%s):\n%s\n", pathStr, address)
	if err := printQR(address); err != nil {
		fmt.Printf("Warning: Could not generate QR Code: %v\n", err)
	}
	return nil
}

func cmdPair(isTestnet bool, accountIdx uint32) error {
	fmt.Println("=== SELA VAULT PAIRING ===")

	// Load Vault first (Fail-fast UX)
	vault, err := LoadVault()
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	fd := int(os.Stdin.Fd())

	// Ask for optional BIP-39 passphrase (Hidden)
	fmt.Print("Enter passphrase (25th word) [Hidden] [Optional]: ")
	passphraseBytes, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Println()
		return fmt.Errorf("reading passphrase: %w", err)
	}
	defer bip.WipeBytes(passphraseBytes)
	fmt.Println() // Newline

	// Ask for vault password (Hidden)
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

	// Decrypt Vault
	fmt.Println("\nDecrypting vault...")

	mnemonicBytes, err := vault.DecryptMnemonic(vaultPass)
	if err != nil {
		return fmt.Errorf("decrypting vault: %w", err)
	}
	defer bip.WipeBytes(mnemonicBytes)
	bip.WipeBytes(vaultPass) // Wipe vault password ASAP

	// Generate BIP-84 account key
	fmt.Println("Deriving BIP-84 account public key...")
	seed := bip.MnemonicToSeed(mnemonicBytes, passphraseBytes)
	defer bip.WipeBytes(seed)
	bip.WipeBytes(mnemonicBytes)   // Wipe mnemonic immediately after seed derivation
	bip.WipeBytes(passphraseBytes) // Wipe passphrase immediately after seed derivation

	deriv, err := bip.DeriveAccountDerivation(seed, isTestnet, accountIdx)
	bip.WipeBytes(seed) // Wipe seed immediately after derivation
	if err != nil {
		return fmt.Errorf("deriving account derivation: %w", err)
	}
	defer deriv.AccountKey.Zero()

	derivedPub, err := deriv.AccountKey.ECPubKey()
	if err != nil {
		return fmt.Errorf("getting public key: %w", err)
	}
	pubKeyBytes := derivedPub.SerializeCompressed()
	chainCode := deriv.AccountKey.ChainCode()

	// Build UR string
	urStr := BuildCryptoAccountUR(deriv.MasterFP, pubKeyBytes, chainCode, deriv.ParentFPBytes, isTestnet, accountIdx)

	fmt.Printf("\nGenerated ur:crypto-account URI:\n%s\n", urStr)
	if err := printQR(urStr); err != nil {
		fmt.Printf("Warning: Could not generate QR Code: %v\n", err)
	}

	return nil
}
