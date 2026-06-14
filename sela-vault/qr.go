package main

import (
	"fmt"

	"rsc.io/qr"
)

// printQR prints a QR Code to the terminal using Unicode half-block characters.
// It uses ANSI escape codes to ensure correct contrast on both light and dark terminal themes.
func printQR(text string) error {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return err
	}

	size := code.Size
	border := 4 // Standard QR code quiet zone is 4 modules

	isBlack := func(x, y int) bool {
		// Quiet zone must be white (light)
		if x < 0 || x >= size || y < 0 || y >= size {
			return false
		}
		return code.Black(x, y)
	}

	// Force black background (\033[40m) and white foreground (\033[97m)
	fmt.Print("\033[40m\033[97m")

	for y := -border; y < size+border; y += 2 {
		for x := -border; x < size+border; x++ {
			topBlack := isBlack(x, y)
			bottomBlack := isBlack(x, y+1)

			// Map top and bottom pixels to terminal characters:
			// - White (light) pixel -> foreground (solid block)
			// - Black (dark) pixel -> background (empty space)
			if !topBlack && !bottomBlack {
				fmt.Print("\u2588") // Both white (█)
			} else if !topBlack && bottomBlack {
				fmt.Print("\u2580") // Top white, bottom black (▀)
			} else if topBlack && !bottomBlack {
				fmt.Print("\u2584") // Top black, bottom white (▄)
			} else {
				fmt.Print(" ") // Both black (space)
			}
		}
		fmt.Println()
	}

	// Reset terminal formatting
	fmt.Print("\033[0m\n")
	return nil
}
