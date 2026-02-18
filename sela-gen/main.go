package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strconv"
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

// generateMnemonic converts 32-byte entropy to 24-word BIP-39 phrase
// Specialized for 256-bit entropy (simplifies checksum logic)
func generateMnemonic(entropy []byte, wordlist []string) (string, error) {
	if len(entropy) != 32 {
		return "", fmt.Errorf("entropy must be 32 bytes")
	}

	// 1. Calculate Checksum (First 8 bits of SHA256)
	hash := sha256.Sum256(entropy)
	checksumByte := hash[0]

	// 2. Convert to Bit String (Entropy + Checksum)
	var bits strings.Builder
	for _, b := range entropy {
		fmt.Fprintf(&bits, "%08b", b)
	}
	fmt.Fprintf(&bits, "%08b", checksumByte) // Append 8 bits checksum

	// 3. Map 11-bit chunks to words
	allBits := bits.String()
	var words []string

	for i := 0; i < len(allBits); i += 11 {
		chunk := allBits[i : i+11]
		idx, _ := strconv.ParseInt(chunk, 2, 64)
		words = append(words, wordlist[idx])
	}

	return strings.Join(words, " "), nil
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

	var entropy []byte

	if choice == "2" {
		for {
			fmt.Print("Enter dice rolls (min 100 digits, 1-6): ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			rolls := strings.TrimSpace(input)

			if len(rolls) < 100 {
				fmt.Println("Error: Need >= 100 rolls")
				continue
			}

			// Whiten with SHA256
			hash := sha256.Sum256([]byte(rolls))
			entropy = hash[:]
			break
		}
	} else {
		entropy = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
			fmt.Println("CRITICAL: System RNG failed:", err)
			os.Exit(1)
		}
	}

	mnemonic, err := generateMnemonic(entropy, wordlist)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Printf("\n--- This is Your Mnemonic Phrase ---\n\n%s\n\n", mnemonic)
	fmt.Println("KEEP SAFE AND OFFLINE ONLY.")
}
