package connect

import (
	"adgo/analyze"
	"crypto/tls"
	"fmt"
	"strings"

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

	scheme, port, tlsConf := securitySettings(c)
	url := fmt.Sprintf("%s://%s:%d", scheme, c.Server, port)

	conn, err := ldap.DialURL(url, ldap.DialWithTLSConfig(tlsConf))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", c.Server, err)
	}

	if c.Security == SecurityStartTLS || c.Security == SecurityInsecureStartTLS {
		if tlsErr := conn.StartTLS(tlsConf); tlsErr != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", tlsErr)
		}
	}

	username, err := formatBindUsername(c)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to format username: %w", err)
	}

	if bindErr := conn.Bind(username, c.Password); bindErr != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind: %w", bindErr)
	}

	return conn, nil
}

// securitySettings gets security configuration
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

	// Determine TLS config
	switch c.Security {
	case SecurityTLS, SecurityStartTLS:
		tlsConf = &tls.Config{
			ServerName:         c.Server,
			InsecureSkipVerify: false,
		}
	case SecurityInsecureTLS, SecurityInsecureStartTLS:
		tlsConf = &tls.Config{
			ServerName:         c.Server,
			InsecureSkipVerify: true,
		}
	default:
		tlsConf = nil
	}

	return scheme, port, tlsConf
}
