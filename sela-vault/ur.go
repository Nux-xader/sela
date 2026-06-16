package main

import (
	"encoding/binary"
	"hash/crc32"
	"strings"

	"github.com/Nux-xader/sela/sela-vault/bip"
)

// bytewordsMinimalTable maps each byte (0x00-0xFF) to its 2-letter Bytewords Minimal representation (Uppercase).
// It is derived from the first and last letters of the 256-word list in BCR-2020-012.
var bytewordsMinimalTable = [256]string{
	"AE", "AD", "AO", "AX", "AA", "AH", "AM", "AT", // 0x00 - 0x07
	"AY", "AS", "BK", "BD", "BN", "BT", "BA", "BS", // 0x08 - 0x0f
	"BE", "BY", "BG", "BW", "BB", "BZ", "CM", "CH", // 0x10 - 0x17
	"CS", "CF", "CY", "CW", "CE", "CA", "CK", "CT", // 0x18 - 0x1f
	"CX", "CL", "CP", "CN", "DK", "DA", "DS", "DI", // 0x20 - 0x27
	"DE", "DT", "DR", "DN", "DW", "DP", "DM", "DL", // 0x28 - 0x2f
	"DY", "EH", "EY", "EO", "EE", "EC", "EN", "EM", // 0x30 - 0x37
	"ET", "ES", "FT", "FR", "FN", "FS", "FM", "FH", // 0x38 - 0x3f
	"FZ", "FP", "FW", "FX", "FY", "FE", "FG", "FL", // 0x40 - 0x47
	"FD", "GA", "GE", "GR", "GS", "GT", "GL", "GW", // 0x48 - 0x4f
	"GD", "GY", "GM", "GU", "GH", "GO", "HF", "HG", // 0x50 - 0x57
	"HD", "HK", "HT", "HP", "HH", "HL", "HY", "HE", // 0x58 - 0x5f
	"HN", "HS", "ID", "IA", "IE", "IH", "IY", "IO", // 0x60 - 0x67
	"IS", "IN", "IM", "JE", "JZ", "JN", "JT", "JL", // 0x68 - 0x6f
	"JO", "JS", "JP", "JK", "JY", "KP", "KO", "KT", // 0x70 - 0x77
	"KS", "KK", "KN", "KG", "KE", "KI", "KB", "LB", // 0x78 - 0x7f
	"LA", "LY", "LF", "LS", "LR", "LP", "LN", "LT", // 0x80 - 0x87
	"LO", "LD", "LE", "LU", "LK", "LG", "MN", "MY", // 0x88 - 0x8f
	"MH", "ME", "MO", "MU", "MW", "MD", "MT", "MS", // 0x90 - 0x97
	"MK", "NL", "NY", "ND", "NS", "NT", "NN", "NE", // 0x98 - 0x9f
	"NB", "OY", "OE", "OT", "OX", "ON", "OL", "OS", // 0xa0 - 0xa7
	"PD", "PT", "PK", "PY", "PS", "PM", "PL", "PE", // 0xa8 - 0xaf
	"PF", "PA", "PR", "QD", "QZ", "RE", "RP", "RL", // 0xb0 - 0xb7
	"RO", "RH", "RD", "RK", "RF", "RY", "RN", "RS", // 0xb8 - 0xbf
	"RT", "SE", "SA", "SR", "SS", "SK", "SW", "ST", // 0xc0 - 0xc7
	"SP", "SO", "SG", "SB", "SF", "SN", "TO", "TK", // 0xc8 - 0xfc
	"TI", "TT", "TD", "TE", "TY", "TL", "TB", "TS", // 0xd0 - 0xd7
	"TP", "TA", "TN", "UY", "UO", "UT", "UE", "UR", // 0xd8 - 0xdf
	"VT", "VY", "VO", "VL", "VE", "VW", "VA", "VD", // 0xe0 - 0xe7
	"VS", "WL", "WD", "WM", "WP", "WE", "WY", "WS", // 0xe8 - 0xef
	"WT", "WN", "WZ", "WF", "WK", "YK", "YN", "YL", // 0xf0 - 0xf7
	"YA", "YT", "ZS", "ZO", "ZT", "ZC", "ZE", "ZM", // 0xf8 - 0xff
}

// encodeBytewordsMinimal encodes a byte slice into Bytewords Minimal string representation.
func encodeBytewordsMinimal(data []byte) string {
	var sb strings.Builder
	sb.Grow(len(data) * 2)
	for _, b := range data {
		sb.WriteString(bytewordsMinimalTable[b])
	}
	return sb.String()
}

// encodeCBORUint encodes an unsigned 32-bit integer according to CBOR rules.
func encodeCBORUint(val uint32) []byte {
	if val <= 23 {
		return []byte{byte(val)}
	}
	if val <= 255 {
		return []byte{0x18, byte(val)}
	}
	if val <= 65535 {
		buf := make([]byte, 3)
		buf[0] = 0x19
		binary.BigEndian.PutUint16(buf[1:], uint16(val))
		return buf
	}
	buf := make([]byte, 5)
	buf[0] = 0x1a
	binary.BigEndian.PutUint32(buf[1:], val)
	return buf
}

// BuildCryptoAccountUR constructs the CBOR bytes for a single BIP-84 account extended public key (m/84'/0'/accountIdx' or m/84'/1'/accountIdx'),
// including the chain code, origin path, and parent fingerprint, then encodes it as a UR.
func BuildCryptoAccountUR(masterFP uint32, accountPubKey []byte, accountChainCode []byte, parentFPBytes []byte, isTestnet bool, accountIdx uint32) string {
	coinByte := byte(0x00)
	if isTestnet {
		coinByte = 0x01
	}

	masterFPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(masterFPBytes, masterFP)

	// Build origin keypath CBOR (Tag 304) dynamically based on accountIdx
	keypathBytes := []byte{
		0xd9, 0x01, 0x30, // Tag 304 prefix
		0xa3,             // Map of 3 elements
		0x01, 0x86,       // Key 1: components array (6 elements)
		0x18, 0x54, 0xf5, // 84' -> [84, true]
		coinByte, 0xf5,   // 0' or 1' -> [0 or 1, true]
	}
	accountIdxBytes := encodeCBORUint(accountIdx)
	keypathBytes = append(keypathBytes, accountIdxBytes...)
	keypathBytes = append(keypathBytes,
		0xf5,       // true (hardened)
		0x02, 0x1a, // Key 2: source fingerprint (uint32) prefix
	)
	keypathBytes = append(keypathBytes, masterFPBytes...)
	keypathBytes = append(keypathBytes,
		0x03, 0x03, // Key 3: depth (3)
	)

	// Clean up transient CBOR encoding slice
	bip.WipeBytes(accountIdxBytes)

	// Build derived-key CBOR (Tag 303)
	hdkeyBytes := []byte{
		0xd9, 0x01, 0x2f, // Tag 303 prefix
		0xa4,             // Map of 4 elements
		0x03, 0x58, 0x21, // Key 3: key-data (33 bytes string prefix)
	}
	hdkeyBytes = append(hdkeyBytes, accountPubKey...)
	hdkeyBytes = append(hdkeyBytes, 0x04, 0x58, 0x20) // Key 4: chain-code prefix
	hdkeyBytes = append(hdkeyBytes, accountChainCode...)
	hdkeyBytes = append(hdkeyBytes, 0x06) // Key 6: origin prefix
	hdkeyBytes = append(hdkeyBytes, keypathBytes...)
	hdkeyBytes = append(hdkeyBytes, 0x08, 0x1a) // Key 8: parent-fingerprint prefix
	hdkeyBytes = append(hdkeyBytes, parentFPBytes...)

	// Build top-level crypto-account CBOR (Tag 311)
	cborBytes := []byte{
		0xd9, 0x01, 0x37, // Tag 311 prefix
		0xa2,       // Map of 2 elements
		0x01, 0x1a, // Key 1: master-fingerprint (uint32) prefix
	}
	cborBytes = append(cborBytes, masterFPBytes...)
	cborBytes = append(cborBytes,
		0x02, 0x81, // Key 2: output-descriptors (array of 1)
		0xd9, 0x01, 0x94, // Tag 404 wrapper prefix
	)
	cborBytes = append(cborBytes, hdkeyBytes...)

	// Calculate CRC32 checksum and build final payload
	checksum := crc32.ChecksumIEEE(cborBytes)
	payload := make([]byte, len(cborBytes)+4)
	copy(payload, cborBytes)
	binary.BigEndian.PutUint32(payload[len(cborBytes):], checksum)

	// Bytewords minimal encoding
	encoded := encodeBytewordsMinimal(payload)

	// Wipe all temporary byte slices containing key material from the memory heap
	bip.WipeBytes(keypathBytes)
	bip.WipeBytes(hdkeyBytes)
	bip.WipeBytes(cborBytes)
	bip.WipeBytes(payload)
	bip.WipeBytes(masterFPBytes)

	return "UR:CRYPTO-ACCOUNT/" + encoded
}
