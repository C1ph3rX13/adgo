package analyze

import (
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// isBinaryLikeString checks if a string contains characteristics of binary data.
// It detects non-printable characters and invalid UTF-8 sequences to determine if the string
// should be treated as binary data rather than text.
//
// Parameters:
//   - s: The string to analyze
//
// Returns:
//   - true if the string appears to be binary data, false if it appears to be text
//
// The function checks for:
//   - Invalid UTF-8 encoding
//   - UTF-8 decode errors (RuneError)
//   - Control characters (excluding tab, newline, carriage return)
//   - DEL character (0x7F)
func isBinaryLikeString(s string) bool {
	if s == "" {
		return false
	}
	// If it's not valid UTF-8, treat as binary
	if !utf8.ValidString(s) {
		return true
	}

	// Check for control characters, excluding common whitespace
	for _, r := range s {
		if r == utf8.RuneError {
			return true
		}
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return true
		}
		if r == 0x7f {
			return true
		}
	}
	return false
}

// attributeHexBytes converts raw bytes to a hexadecimal string with "0x" prefix.
// This is used to display binary data that cannot be otherwise formatted.
//
// Parameters:
//   - raw: The raw bytes to convert
//
// Returns:
//   - A hexadecimal string representation with "0x" prefix (uppercase)
func attributeHexBytes(raw []byte) string {
	return "0x" + strings.ToUpper(hex.EncodeToString(raw))
}
