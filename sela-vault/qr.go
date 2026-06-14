package main

import (
	"fmt"

	"rsc.io/qr"
)

// printQR prints a QR Code to the terminal.
// It uses ANSI escape codes to ensure correct contrast (black background, white foreground)
// across both light and dark terminal themes, using two characters per module to keep it square.
func printQR(text string) error {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return err
	}

	// Set terminal background to black (\033[40m) and foreground to white (\033[97m)
	fmt.Print("\033[40m\033[97m")

	border := 2
	for y := -border; y < code.Size+border; y++ {
		for x := -border; x < code.Size+border; x++ {
			// Check if pixel is inside boundaries and is black
			isBlack := x >= 0 && x < code.Size && y >= 0 && y < code.Size && code.Black(x, y)
			if isBlack {
				fmt.Print("  ")         // Black module (empty space)
				continue
			}
			fmt.Print("\u2588\u2588") // White module (solid block)
		}
		fmt.Println()
	}

	// Reset terminal formatting
	fmt.Print("\033[0m\n")
	return nil
}
