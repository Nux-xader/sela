package util

import (
	"crypto/rand"
	"runtime"
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
