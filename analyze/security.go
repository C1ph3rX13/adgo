package analyze

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAP Security Modes
const (
	SecurityModeNone      = 0
	SecurityModeTLS       = 1
	SecurityModeStartTLS  = 2
	SecurityModeInsecureTLS     = 3
	SecurityModeInsecureStartTLS = 4
)

// securityModeNames maps security mode values to their string representations
var securityModeNames = map[int]string{
	SecurityModeNone:      "None",
	SecurityModeTLS:       "TLS",
	SecurityModeStartTLS:  "StartTLS",
	SecurityModeInsecureTLS:     "InsecureTLS",
	SecurityModeInsecureStartTLS: "InsecureStartTLS",
}

// SecurityModeName returns the string representation of a security mode.
// Returns an error if the mode is invalid.
func SecurityModeName(mode int) (string, error) {
	name, ok := securityModeNames[mode]
	if !ok {
		return "", fmt.Errorf("invalid security mode: %d", mode)
	}
	return name, nil
}

// IsValidSecurityMode checks if the given security mode is valid.
func IsValidSecurityMode(mode int) bool {
	_, ok := securityModeNames[mode]
	return ok
}

// encryptionType represents a single encryption type flag with its bit position and name.
// This is used to decode the msDS-SupportedEncryptionTypes attribute value.
type encryptionType struct {
	bit  uint64 // Bit flag for this encryption type (power of 2)
	name string // Human-readable name of the encryption type
}

// Pre-defined encryption types to avoid allocation on every call
var encryptionTypes = []encryptionType{
	{1 << 0, "DES_CBC_CRC"},
	{1 << 1, "DES_CBC_MD5"},
	{1 << 2, "RC4_HMAC"},
	{1 << 3, "AES128_CTS_HMAC_SHA1_96"},
	{1 << 4, "AES256_CTS_HMAC_SHA1_96"},
	{1 << 5, "FAST_Supported"},
	{1 << 6, "Compound_Identity_Supported"},
	{1 << 7, "Claims_Supported"},
	{1 << 8, "Resource_SID_Compression_Disabled"},
	{1 << 9, "AES256_CTS_HMAC_SHA1_96_SK"},
}

// MSDSSupportedEncryptionTypes parses msDS-SupportedEncryptionTypes attribute
// https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
func MSDSSupportedEncryptionTypes(entry *ldap.Entry, attribute string) (string, error) {
	b := entry.GetAttributeValue(attribute)

	// Convert to 32-bit unsigned integer
	mask, err := strconv.ParseUint(b, 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid encryption types value: %w", err)
	}

	// Parse supported encryption types
	var supported []string
	for _, t := range encryptionTypes {
		if mask&t.bit != 0 {
			supported = append(supported, t.name)
		}
	}

	// Handle undefined high bits (bits 10-31)
	if remaining := mask &^ ((1 << 10) - 1); remaining != 0 {
		supported = append(supported, fmt.Sprintf("UNKNOWN_BITS(0x%X)", remaining))
	}

	// Handle empty result
	if len(supported) == 0 {
		return fmt.Sprintf("NONE(0x%X)", mask), nil
	}
	return strings.Join(supported, " | "), nil
}

// AttributeHex
// Parses msDS-GenerationId, logonHours, msDS-AllowedToActOnBehalfOfOtherIdentity attributes
func AttributeHex(entry *ldap.Entry, attribute string) (string, error) {
	// Use GetRawAttributeValue for binary attributes
	rawValue := entry.GetRawAttributeValue(attribute)
	if len(rawValue) == 0 {
		return "", nil
	}

	// Convert binary data to hex string with 0x prefix
	hexStr := attributeHexBytes(rawValue)

	// Special handling for msDS-AllowedToActOnBehalfOfOtherIdentity attribute
	if attribute == AttrMSDSAllowedToActOnBehalfOfOtherIdentity {
		sids, err := ParseRBCDBinary(rawValue)
		if err != nil || len(sids) == 0 {
			return hexStr, nil
		}
		return strings.Join(sids, ", "), nil
	}

	return hexStr, nil
}

// ParseRBCDBinary parses msDS-AllowedToActOnBehalfOfOtherIdentity binary data to extract SIDs
func ParseRBCDBinary(data []byte) ([]string, error) {
	// msDS-AllowedToActOnBehalfOfOtherIdentity binary structure:
	// - Starts with 0x01 (Revision)
	// - Followed by ACE structure containing SIDs
	// This is a simplified parser that extracts SIDs from binary data

	var sids []string

	// Check minimum length
	if len(data) < 8 {
		return sids, nil
	}

	// Simplified parsing: look for SID signatures (0x01 followed by 0x05 for Windows SIDs)
	for i := 0; i < len(data)-8; i++ {
		if data[i] != 0x01 {
			continue
		}

		subAuthCount := int(data[i+1]) & 0xFF
		sidLen := 8 + subAuthCount*4
		if sidLen < 8 || i+sidLen > len(data) {
			continue
		}

		if data[i+2] != 0x00 || data[i+3] != 0x00 || data[i+4] != 0x00 || data[i+5] != 0x00 || data[i+6] != 0x00 || data[i+7] != 0x05 {
			continue
		}

		sid, err := ParseObjectSID(data[i : i+sidLen])
		if err != nil {
			continue
		}
		sids = append(sids, sid)
		i += sidLen - 1
	}

	return sids, nil
}
