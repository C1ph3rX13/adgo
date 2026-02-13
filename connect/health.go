package connect

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// Ping performs a health check by querying the RootDSE
// This can be used to verify the connection is still alive
func (c *ldapClient) Ping(ctx context.Context) error {
	if c.conn == nil {
		return fmt.Errorf("connection is nil")
	}

	// Query RootDSE to verify connection
	searchReq := ldap.NewSearchRequest(
		"", // RootDSE has empty base DN
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,     // Size limit: only need 1 entry
		0,     // Time limit: no server-side timeout
		false,
		"(objectClass=*)",
		[]string{"vendorName", "supportedLDAPVersion", "supportedExtensions"},
		nil,
	)

	// Execute search with context support
	sr, err := c.conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return fmt.Errorf("no entries returned from RootDSE")
	}

	return nil
}
