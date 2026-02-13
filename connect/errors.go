package connect

import (
	"fmt"
	"strings"
)

// LDAPError represents an LDAP operation error with context
type LDAPError struct {
	Operation string            // Operation type: connect, bind, search, etc.
	Context   map[string]interface{} // Additional context about the error
	Err       error             // Underlying error
}

// Error returns the formatted error message
func (e *LDAPError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("LDAP %s failed", e.Operation))

	if len(e.Context) > 0 {
		sb.WriteString(" [")
		first := true
		for k, v := range e.Context {
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%s=%v", k, v))
			first = false
		}
		sb.WriteString("]")
	}

	if e.Err != nil {
		sb.WriteString(fmt.Sprintf(": %v", e.Err))
	}

	return sb.String()
}

// Unwrap returns the underlying error for error unwrapping
func (e *LDAPError) Unwrap() error {
	return e.Err
}

// NewLDAPError creates a new LDAP error
func NewLDAPError(operation string, context map[string]interface{}, err error) error {
	return &LDAPError{
		Operation: operation,
		Context:   context,
		Err:       err,
	}
}

// WrapConnectError wraps a connection error
func WrapConnectError(server string, err error) error {
	return &LDAPError{
		Operation: "connect",
		Context:   map[string]interface{}{"server": server},
		Err:       err,
	}
}

// WrapBindError wraps a bind/authentication error
func WrapBindError(username string, err error) error {
	return &LDAPError{
		Operation: "bind",
		Context:   map[string]interface{}{"username": username},
		Err:       err,
	}
}

// WrapQueryError wraps a search query error
func WrapQueryError(filter string, err error) error {
	return &LDAPError{
		Operation: "query",
		Context:   map[string]interface{}{"filter": filter},
		Err:       err,
	}
}

// WrapSearchError wraps a search execution error
func WrapSearchError(baseDN string, err error) error {
	return &LDAPError{
		Operation: "search",
		Context:   map[string]interface{}{"baseDN": baseDN},
		Err:       err,
	}
}

// IsRetryableError checks if an error is retryable (network, timeout, etc)
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's an LDAPError
	if ldapErr, ok := err.(*LDAPError); ok {
		err = ldapErr.Err // unwrap to check underlying error
	}

	// Network errors, timeout errors, and server unavailable are retryable
	errStr := err.Error()

	retryablePatterns := []string{
		"connection reset",
		"connection refused",
		"timeout",
		"i/o timeout",
		"network is unreachable",
		"no route to host",
		"temporary failure",
		"ldap server down",
		"server busy",
		"unavailable",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}

// IsAuthError checks if an error is authentication-related
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's an LDAPError with bind operation
	if ldapErr, ok := err.(*LDAPError); ok {
		if ldapErr.Operation == "bind" {
			return true
		}
		err = ldapErr.Err // unwrap to check underlying error
	}

	errStr := err.Error()

	authPatterns := []string{
		"invalid credentials",
		"authentication failed",
		"bind failed",
		"login failed",
		"unauthorized",
		"access denied",
	}

	for _, pattern := range authPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}

// IsTLSError checks if an error is TLS-related
func IsTLSError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	tlsErrorPatterns := []string{
		"tls",
		"handshake failure",
		"protocol version",
		"unsupported protocol",
		"no supported versions",
		"certificate",
		"x509",
	}

	for _, pattern := range tlsErrorPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}
