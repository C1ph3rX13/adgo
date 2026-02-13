package cmd

import (
	"adgo/analyze"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxDNLength     = 2048  // Maximum DN length
	MaxFilterLength = 4096 // Maximum LDAP filter length
)

// dangerousChars contains characters that could be used in LDAP injection
var dangerousChars = []string{"*", "(", ")", "&", "|", "!", "=", "<", ">"}

// LDAPInputError represents an input validation error
type LDAPInputError struct {
	Field   string
	Value   string
	Reason  string
}

func (e *LDAPInputError) Error() string {
	return fmt.Sprintf("LDAP input validation failed for %s: %s (value: %s)", e.Field, e.Reason, e.Value)
}

// SanitizeLDAPInput validates and sanitizes user-provided LDAP input
// Returns an error if the input contains dangerous characters or exceeds length limits
func SanitizeLDAPInput(input string, allowFilterChars bool) error {
	// Check for nil/empty input
	if strings.TrimSpace(input) == "" {
		return fmt.Errorf("LDAP input cannot be empty")
	}

	// Check length
	if len(input) > MaxFilterLength {
		return &LDAPInputError{
			Field:  "input",
			Value:  truncateForDisplay(input),
			Reason: fmt.Sprintf("exceeds maximum length of %d", MaxFilterLength),
		}
	}

	// If filter characters are not allowed, check for dangerous characters
	if !allowFilterChars {
		for _, char := range dangerousChars {
			if strings.Contains(input, char) {
				return &LDAPInputError{
					Field:  "input",
					Value:  truncateForDisplay(input),
					Reason: fmt.Sprintf("contains potentially dangerous character: '%s'", char),
				}
			}
		}
	}

	return nil
}

// ValidateFilter validates an LDAP search filter
func ValidateFilter(filter string) error {
	if filter == "" {
		return fmt.Errorf("filter cannot be empty")
	}

	if len(filter) > MaxFilterLength {
		return fmt.Errorf("filter exceeds maximum length of %d", MaxFilterLength)
	}

	// Check for balanced parentheses
	openCount := strings.Count(filter, "(")
	closeCount := strings.Count(filter, ")")
	if openCount != closeCount {
		return fmt.Errorf("filter contains unbalanced parentheses")
	}

	// Basic filter syntax validation - should start with (
	if !strings.HasPrefix(filter, "(") {
		return fmt.Errorf("filter must start with '('")
	}

	// And end with )
	if !strings.HasSuffix(filter, ")") {
		return fmt.Errorf("filter must end with ')'")
	}

	return nil
}

// ValidateAttribute validates an LDAP attribute name
func ValidateAttribute(attr string) error {
	if attr == "" {
		return fmt.Errorf("attribute name cannot be empty")
	}

	// Attribute names should be alphanumeric and may contain hyphen
	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9-]*$`, attr)
	if !matched {
		return fmt.Errorf("attribute contains invalid characters (must start with letter, contain only letters, numbers, hyphens)")
	}

	return nil
}

// ValidateAttributes validates multiple LDAP attributes
func ValidateAttributes(attrs []string) error {
	for _, attr := range attrs {
		if err := ValidateAttribute(attr); err != nil {
			return err
		}
	}
	return nil
}

// truncateForDisplay truncates a string for display in error messages
func truncateForDisplay(s string) string {
	const maxDisplay = 50
	if len(s) <= maxDisplay {
		return s
	}
	return s[:maxDisplay] + "..."
}


// ValidatePort validates that a port number is within the valid range (1-65535).
func ValidatePort(port int) error {
	if port < analyze.MinPort || port > analyze.MaxPort {
		return fmt.Errorf("port must be between %d and %d", analyze.MinPort, analyze.MaxPort)
	}
	return nil
}

// ValidatePortString validates a port number provided as a string.
func ValidatePortString(portStr string) error {
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("port must be a number")
	}
	return ValidatePort(p)
}

// ValidateSecurityMode validates that a security mode is within the valid range (0-4).
func ValidateSecurityMode(mode int) error {
	if !analyze.IsValidSecurityMode(mode) {
		return fmt.Errorf("security mode must be between %d and %d",
			analyze.SecurityModeNone, analyze.SecurityModeInsecureStartTLS)
	}
	return nil
}

// ValidateSecurityModeString validates a security mode provided as a string.
func ValidateSecurityModeString(modeStr string) error {
	s, err := strconv.Atoi(modeStr)
	if err != nil {
		return fmt.Errorf("security mode must be a number")
	}
	return ValidateSecurityMode(s)
}

// ValidateOutputFormat validates that the output format is supported.
func ValidateOutputFormat(format string) error {
	switch format {
	case analyze.OutputFormatText, analyze.OutputFormatJSON, analyze.OutputFormatCSV, "bloodhound", "bh":
		return nil
	default:
		return fmt.Errorf("output format must be text, json, csv, or bloodhound")
	}
}

// ValidateBaseDN validates that a base DN string appears to be a valid distinguished name.
// This is a basic check - it only verifies that "DC=" is present.
func ValidateBaseDN(dn string) error {
	if dn == "" {
		return nil // Empty DN is allowed (will be set later)
	}
	if !strings.Contains(strings.ToUpper(dn), "DC=") {
		return fmt.Errorf("base DN usually contains 'DC=' components")
	}
	return nil
}

// ValidateServer validates that a server address is not empty.
func ValidateServer(server string) error {
	if strings.TrimSpace(server) == "" {
		return fmt.Errorf("server address cannot be empty")
	}
	return nil
}

// ValidateUsername validates that a username is not empty.
func ValidateUsername(username string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username cannot be empty")
	}
	return nil
}
