package connect

import (
	"adgo/analyze"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// SecurityType defines connection security type
type SecurityType int

const (
	SecurityNone             SecurityType = 0
	SecurityTLS              SecurityType = 1
	SecurityStartTLS         SecurityType = 2
	SecurityInsecureTLS      SecurityType = 3
	SecurityInsecureStartTLS SecurityType = 4
)

// LoginName username type
type LoginName string

const (
	UserPrincipalName LoginName = analyze.DefaultLoginName
	SAMAccountName    LoginName = "sAMAccountName"
)

// Config LDAP connection configuration
type Config struct {
	Server    string       `mapstructure:"server"`    // LDAP server address
	Port      int          `mapstructure:"port"`      // LDAP server port
	BaseDN    string       `mapstructure:"baseDN"`    // LDAP base DN
	Username  string       `mapstructure:"username"`  // LDAP username
	Password  string       `mapstructure:"password"`  // LDAP password
	LoginName LoginName    `mapstructure:"loginName"` // Username type for authentication
	Security  SecurityType `mapstructure:"security"`  // Connection security type
	Timeout   int          `mapstructure:"timeout"`   // Connection timeout in seconds (default: 30)
	SizeLimit int          `mapstructure:"sizeLimit"` // Maximum number of entries to return (0 = unlimited)
}

func formatBindUsername(c *Config) (string, error) {
	username := strings.TrimSpace(c.Username)
	if username == "" {
		return "", fmt.Errorf("LDAP username is not configured")
	}

	switch c.LoginName {
	case SAMAccountName:
		return username, nil
	case UserPrincipalName, "":
		return UserPrincipal(c.BaseDN, username)
	default:
		return UserPrincipal(c.BaseDN, username)
	}
}

func ldapBind(c *Config) (*ldap.Conn, error) {
	if c.Server == "" {
		return nil, fmt.Errorf("LDAP server is not configured")
	}

	scheme, port, baseTLSConf := securitySettings(c)
	url := fmt.Sprintf("%s://%s:%d", scheme, c.Server, port)

	// Create dialer with timeout configuration
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout == 0 {
		timeout = time.Duration(analyze.DefaultConnectionTimeout) * time.Second
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// For non-TLS connections, connect directly
	if baseTLSConf == nil {
		conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", c.Server, err)
		}

		username, err := formatBindUsername(c)
		if err != nil {
			defer conn.Close()
			return nil, fmt.Errorf("failed to format username: %w", err)
		}

		if bindErr := conn.Bind(username, c.Password); bindErr != nil {
			defer conn.Close()
			return nil, fmt.Errorf("failed to bind: %w", bindErr)
		}

		return conn, nil
	}

	// For TLS connections, try with intelligent version negotiation
	conn, err := dialWithTLSNegotiation(url, dialer, baseTLSConf, c)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", c.Server, err)
	}

	username, err := formatBindUsername(c)
	if err != nil {
		defer conn.Close()
		return nil, fmt.Errorf("failed to format username: %w", err)
	}

	if bindErr := conn.Bind(username, c.Password); bindErr != nil {
		defer conn.Close()
		return nil, fmt.Errorf("failed to bind: %w", bindErr)
	}

	return conn, nil
}

// securitySettings gets base security configuration (TLS version negotiation handled separately)
func securitySettings(c *Config) (string, int, *tls.Config) {
	scheme := "ldap"
	port := c.Port
	var tlsConf *tls.Config

	// Determine scheme and default port
	switch c.Security {
	case SecurityTLS, SecurityInsecureTLS:
		scheme = "ldaps"
		if port == 0 {
			port = 636
		}
	case SecurityStartTLS, SecurityInsecureStartTLS:
		scheme = "ldap"
		if port == 0 {
			port = 389
		}
	default: // SecurityNone
		scheme = "ldap"
		if port == 0 {
			port = 389
		}
	}

	// Determine base TLS config (version will be negotiated)
	switch c.Security {
	case SecurityTLS, SecurityStartTLS:
		tlsConf = &tls.Config{
			ServerName:         c.Server,
			InsecureSkipVerify: false,
			// MinVersion set during negotiation
		}
	case SecurityInsecureTLS, SecurityInsecureStartTLS:
		tlsConf = &tls.Config{
			ServerName:         c.Server,
			InsecureSkipVerify: true,
			// MinVersion set during negotiation
		}
	default:
		tlsConf = nil
	}

	return scheme, port, tlsConf
}

// tlsVersionInfo represents a TLS version to try
type tlsVersionInfo struct {
	version uint16
	name    string
}

// dialWithTLSNegotiation attempts to connect with progressive TLS version fallback
// For Red Team scenarios: prioritize modern TLS but gracefully fallback for legacy DCs
func dialWithTLSNegotiation(url string, dialer *net.Dialer, baseTLSConf *tls.Config, c *Config) (*ldap.Conn, error) {
	// Define TLS versions to try, in order of preference
	// For Red Team: Start with TLS 1.2+, fallback to 1.0 for legacy DCs (Win2003/2008)
	versionsToTry := []tlsVersionInfo{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"}, // For legacy DCs
		{tls.VersionTLS10, "TLS 1.0"}, // For very old DCs (Win2003)
	}

	var lastErr error

	// Try each TLS version
	for i, tlsVer := range versionsToTry {
		// Clone the base config to avoid modifying the original
		tlsConf := baseTLSConf.Clone()
		tlsConf.MinVersion = tlsVer.version
		if i < len(versionsToTry)-1 {
			// Set MaxVersion to current attempt to prevent version jumping
			tlsConf.MaxVersion = tlsVer.version
		}

		// Attempt connection
		conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConf))
		if err == nil {
			// For StartTLS, need to call StartTLS
			if c.Security == SecurityStartTLS || c.Security == SecurityInsecureStartTLS {
				if startTLSErr := conn.StartTLS(tlsConf); startTLSErr != nil {
					conn.Close()
					lastErr = fmt.Errorf("TLS %s handshake failed: %w", tlsVer.name, startTLSErr)
					continue // Try next version
				}
			}

			// Success! Log the TLS version used
			if i > 0 {
				fmt.Printf("[!] Connected using %s (legacy TLS version)\n", tlsVer.name)
			}
			return conn, nil
		}

		// Save error for next attempt
		lastErr = err

		// Check if error indicates TLS version mismatch
		if isTLSError(err) {
			continue // Try next version
		}

		// Other errors (network, timeout, etc) shouldn't retry
		break
	}

	// All versions failed
	return nil, fmt.Errorf("TLS version negotiation failed (tried TLS 1.3, 1.2, 1.1, 1.0): %w", lastErr)
}

// isTLSError checks if an error is related to TLS version incompatibility
func isTLSError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	tlsErrorStrings := []string{
		"tls",
		"handshake failure",
		"protocol version",
		"unsupported protocol",
		"no supported versions",
		"connection reset by peer",
	}

	lowerErr := strings.ToLower(errStr)
	for _, tlsStr := range tlsErrorStrings {
		if strings.Contains(lowerErr, strings.ToLower(tlsStr)) {
			return true
		}
	}

	return false
}
