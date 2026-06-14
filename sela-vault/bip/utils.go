package bip

import "runtime"

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
