package analyze

import (
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// isBinaryLikeString checks if the string contains non-printable characters
// or is invalid UTF-8, indicating it might be binary data.
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

// attributeHexBytes converts raw bytes to a hex string with 0x prefix
func attributeHexBytes(raw []byte) string {
	return "0x" + strings.ToUpper(hex.EncodeToString(raw))
}
