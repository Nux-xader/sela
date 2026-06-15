package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// --- CORE LOGIC ---

func loadWordlist(filename string) ([]string, error) {
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

// wipeBytes securely overwrites a byte slice with zeros to clear RAM trace.
func wipeBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// generateMnemonic converts 32-byte entropy to 24-word BIP-39 phrase.
// It returns a byte slice so it can be wiped from memory after use.
func generateMnemonic(entropy []byte, wordlist []string) ([]byte, error) {
	if len(entropy) != 32 {
		return nil, fmt.Errorf("entropy must be 32 bytes")
	}

	// 1. Calculate Checksum (First 8 bits of SHA256)
	hash := sha256.Sum256(entropy)
	defer wipeBytes(hash[:]) // Zero-out intermediate hash in RAM
	checksumByte := hash[0]

	// 2. Convert to Bit Array (Entropy + Checksum)
	// Total bits = 256 + 8 = 264 bits
	bits := make([]byte, 264)
	defer wipeBytes(bits)

	for i, b := range entropy {
		for j := range 8 {
			bits[i*8+j] = (b >> uint(7-j)) & 1
		}
	}
	for j := range 8 {
		bits[256+j] = (checksumByte >> uint(7-j)) & 1
	}

	// 3. Map 11-bit chunks to words
	var words [][]byte
	for i := 0; i < 264; i += 11 {
		var idx int64
		for j := range 11 {
			idx = (idx << 1) | int64(bits[i+j])
		}
		words = append(words, []byte(wordlist[idx]))
	}

	mnemonicBytes := bytes.Join(words, []byte(" "))
	// Clean up intermediate word slices
	for i := range words {
		wipeBytes(words[i])
	}
	return mnemonicBytes, nil
}

// --- MAIN CLI ---

func main() {
	fmt.Println("--- SELA: sela-gen (256-bit) ---")

	wordlist, err := loadWordlist("../bip-39-english.txt")
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Print("Mode [1=System RNG, 2=Dice]: ")
	var choice string
	fmt.Scanln(&choice)

	entropy := make([]byte, 32)
	defer wipeBytes(entropy) // Backup cleanup

	if choice == "2" {
		for {
			fmt.Print("Enter dice rolls (min 100 digits, 1-6): ")

			reader := bufio.NewReader(os.Stdin)
			inputBytes, err := reader.ReadBytes('\n')

			if err != nil {
				fmt.Println("Error reading input:", err)
				if inputBytes != nil {
					wipeBytes(inputBytes)
				}
				continue
			}
			rollsBytes := bytes.TrimSpace(inputBytes)

			if len(rollsBytes) < 100 {
				fmt.Println("Error: Need >= 100 rolls")
				wipeBytes(inputBytes)
				continue
			}

			// SELA-01: Validate that all characters are digits 1-6
			isValid := true
			for _, b := range rollsBytes {
				if b < '1' || b > '6' {
					isValid = false
					break
				}
			}
			if !isValid {
				fmt.Println("Error: Input must contain only digits between 1 and 6")
				wipeBytes(inputBytes)
				continue
			}

			// Whiten with SHA256
			hash := sha256.Sum256(rollsBytes)
			copy(entropy, hash[:])
			wipeBytes(hash[:]) // Wipe intermediate hash immediately
			wipeBytes(inputBytes)
			break
		}
	} else {
		if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
			fmt.Println("CRITICAL: System RNG failed:", err)
			os.Exit(1)
		}
	}

	mnemonic, err := generateMnemonic(entropy, wordlist)
	wipeBytes(entropy) // Wipe entropy immediately after generation
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Println("\n--- This is Your Mnemonic Phrase ---")
	fmt.Println()
	os.Stdout.Write(mnemonic)
	wipeBytes(mnemonic)
	fmt.Println()
	fmt.Println()
	fmt.Println("KEEP SAFE AND OFFLINE ONLY.")

	fmt.Print("\nPress [Enter] to clear terminal, wipe mnemonic from RAM, and exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// Clear screen and scrollback buffer using ANSI escape codes
	fmt.Print("\033[H\033[2J\033[3J")
}
