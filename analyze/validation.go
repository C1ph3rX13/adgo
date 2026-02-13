package analyze

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// LDAP input validation limits
	MaxDNLength     = 2048 // Maximum DN length
	MaxFilterLength = 4096 // Maximum LDAP filter length
)

// ValidateDN validates an LDAP Distinguished Name
func ValidateDN(dn string) error {
	if dn == "" {
		return nil // Empty DN is allowed
	}

	if len(dn) > MaxDNLength {
		return NewValidationError("DN", dn, "exceeds maximum length")
	}

	// Check for valid DN prefix
	validPrefixes := []string{"CN=", "OU=", "DC="}
	hasValidPrefix := false
	for _, prefix := range validPrefixes {
		if startsWithIgnoreCase(dn, prefix) {
			hasValidPrefix = true
			break
		}
	}

	if !hasValidPrefix {
		return NewValidationError("DN", dn, "must start with a valid prefix (CN=, OU=, DC=)")
	}

	return nil
}

// ValidateFilter validates an LDAP search filter
func ValidateFilter(filter string) error {
	if filter == "" {
		return NewValidationError("filter", filter, "cannot be empty")
	}

	if len(filter) > MaxFilterLength {
		return NewValidationError("filter", filter, "exceeds maximum length")
	}

	// Check for balanced parentheses
	openCount := countChar(filter, '(')
	closeCount := countChar(filter, ')')
	if openCount != closeCount {
		return NewValidationError("filter", filter, "contains unbalanced parentheses")
	}

	// Basic filter syntax validation
	if !strings.HasPrefix(filter, "(") {
		return NewValidationError("filter", filter, "must start with '('")
	}

	if !strings.HasSuffix(filter, ")") {
		return NewValidationError("filter", filter, "must end with ')'")
	}

	return nil
}

// ValidateAttribute validates an LDAP attribute name
func ValidateAttribute(attr string) error {
	if attr == "" {
		return NewValidationError("attribute", attr, "cannot be empty")
	}

	// Attribute names should be alphanumeric and may contain hyphen
	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9-]*$`, attr)
	if !matched {
		return NewValidationError("attribute", attr, "contains invalid characters (must start with letter, contain only letters, numbers, hyphens)")
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

// ValidateBaseDN checks if a Base DN string appears to be valid
func ValidateBaseDN(dn string) error {
	if dn == "" {
		return nil // Empty DN is allowed
	}

	if !strings.Contains(strings.ToUpper(dn), "DC=") {
		return NewValidationError("BaseDN", dn, "should contain 'DC=' components")
	}

	return nil
}

// countChar counts occurrences of a character in a string
func countChar(s string, c byte) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			count++
		}
	}
	return count
}

// startsWithIgnoreCase checks if a string starts with a prefix (case-insensitive)
func startsWithIgnoreCase(s, prefix string) bool {
	return len(s) >= len(prefix) && (s[:len(prefix)] == prefix || len(s) > len(prefix) && hasPrefixCase(s, prefix))
}

// hasPrefixCase checks if string has prefix with matching case
func hasPrefixCase(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}

	// Try exact match first
	if s[:len(prefix)] == prefix {
		return true
	}

	// Try case-insensitive match
	sLower := toLower(s)
	prefixLower := toLower(prefix)

	for i := 0; i < len(prefix); i++ {
		if sLower[i] == prefixLower[i] && sLower[i:i+len(prefix)] == prefixLower[i:] {
			return true
		}
	}

	return false
}

// toLower converts a string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// NewValidationError creates a new validation error
func NewValidationError(field, value, reason string) error {
	return &ValidationError{
		Field:  field,
		Value:  value,
		Reason: reason,
	}
}

// ValidationError represents an input validation error
type ValidationError struct {
	Field  string
	Value  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s validation failed: %s (value: %s)", e.Field, e.Reason, e.Value)
}
