package util

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

// WipeBytes securely overwrites a byte slice with zeros to clear RAM trace.
func WipeBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// GenerateConfirmCode generates a random 5-character alphanumeric confirmation code.
func GenerateConfirmCode() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude confusing chars: 0, O, I, 1
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// ReadSecretLine reads a line from stdin byte-by-byte without internal buffering.
// It returns a slice pointing to a pre-allocated buffer that can be securely wiped.
func ReadSecretLine() ([]byte, error) {
	buf := make([]byte, 1024)
	var idx int
	var b [1]byte
	for {
		n, err := os.Stdin.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			if b[0] == '\r' {
				continue
			}
			if idx < len(buf) {
				buf[idx] = b[0]
				idx++
			} else {
				WipeBytes(buf)
				return nil, fmt.Errorf("input too long")
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			WipeBytes(buf)
			return nil, err
		}
	}
	return buf[:idx], nil
}

// ReadSecretPassword reads a password from the terminal without echoing it.
// It avoids using term.ReadPassword to prevent Go from allocating
// unwipeable intermediate string/slice buffers in RAM.
func ReadSecretPassword(fd int) ([]byte, error) {
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, oldState)

	buf := make([]byte, 1024)
	var idx int
	var b [1]byte

	for {
		n, err := os.Stdin.Read(b[:])
		if n > 0 {
			char := b[0]
			
			// Enter (CR or LF)
			if char == '\n' || char == '\r' {
				break
			}
			
			// Backspace (127) or Ctrl+H (8)
			if char == 127 || char == 8 {
				if idx > 0 {
					idx--
					buf[idx] = 0 // Wipe the actual character
				}
				continue
			}
			
			// Ctrl+C (3)
			if char == 3 {
				WipeBytes(buf)
				return nil, fmt.Errorf("interrupted")
			}
			
			// Ctrl+D (4)
			if char == 4 && idx == 0 {
				break
			}

			if idx < len(buf) {
				buf[idx] = char
				idx++
			} else {
				WipeBytes(buf)
				return nil, fmt.Errorf("password too long")
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			WipeBytes(buf)
			return nil, err
		}
	}

	return buf[:idx], nil
}
