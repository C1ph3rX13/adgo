package connect

import (
	"adgo/analyze"
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// Client defines LDAP client interface
type Client interface {
	Search(ctx context.Context, filter string, attributes []string) ([]*ldap.Entry, error)
	StreamSearch(ctx context.Context, filter string, attributes []string) (<-chan *ldap.Entry, <-chan error)
	Close() error
}

// ldapClient implements Client interface
type ldapClient struct {
	config        *Config
	conn          *ldap.Conn
	supportPaging bool // cache whether server supports paging
}

// NewClient creates and initializes a new LDAP client
func NewClient(c *Config) (Client, error) {
	if c == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	conn, err := ldapBind(c)
	if err != nil {
		return nil, fmt.Errorf("failed to connect/bind to LDAP server: %w", err)
	}

	client := &ldapClient{
		config: c,
		conn:   conn,
	}

	// Probe server capabilities (e.g. paging support)
	client.checkCapabilities()

	return client, nil
}

// Close closes the LDAP connection
func (c *ldapClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// checkCapabilities checks for supported controls (paging)
func (c *ldapClient) checkCapabilities() {
	// Query RootDSE for supported controls
	searchReq := ldap.NewSearchRequest(
		"", // RootDSE BaseDN is empty
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	)

	sr, err := c.conn.Search(searchReq)
	if err != nil {
		return
	}

	if len(sr.Entries) > 0 {
		controls := sr.Entries[0].GetAttributeValues("supportedControl")
		for _, ctrl := range controls {
			if ctrl == analyze.OIDControlTypePaging {
				c.supportPaging = true
				break
			}
		}
	}
}

// Search executes LDAP search
// Automatically enables paging if supported
func (c *ldapClient) Search(ctx context.Context, filter string, attributes []string) ([]*ldap.Entry, error) {
	var entries []*ldap.Entry

	err := c.executeSearch(ctx, filter, attributes, func(pageEntries []*ldap.Entry) error {
		entries = append(entries, pageEntries...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return entries, nil
}

// StreamSearch executes LDAP search and streams results via channel
// Automatically handles pagination and sends entries as they are received
func (c *ldapClient) StreamSearch(ctx context.Context, filter string, attributes []string) (<-chan *ldap.Entry, <-chan error) {
	entriesChan := make(chan *ldap.Entry, 100) // Buffer for better throughput
	errChan := make(chan error, 1)

	go func() {
		defer close(entriesChan)
		defer close(errChan)

		err := c.executeSearch(ctx, filter, attributes, func(pageEntries []*ldap.Entry) error {
			for _, entry := range pageEntries {
				select {
				case entriesChan <- entry:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})

		if err != nil {
			errChan <- err
		}
	}()

	return entriesChan, errChan
}

// executeSearch handles the core search logic with pagination
func (c *ldapClient) executeSearch(ctx context.Context, filter string, attributes []string, handler func([]*ldap.Entry) error) error {
	// 1. Build base search request
	searchReq := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // SizeLimit: 0 means unlimited
		0, // TimeLimit: 0 means unlimited
		false,
		filter,
		attributes,
		nil, // Controls added later based on capabilities
	)

	// 2. Add paging control if supported
	var pagingControl *ldap.ControlPaging
	if c.supportPaging {
		pagingControl = ldap.NewControlPaging(uint32(analyze.DefaultPagingSize))
		searchReq.Controls = []ldap.Control{pagingControl}
	}

	for {
		select {
		case <-ctx.Done():
			if pagingControl != nil {
				_ = c.abandonPaging(searchReq)
			}
			return ctx.Err()
		default:
		}

		// Execute search
		result, err := c.conn.Search(searchReq)
		if err != nil {
			if pagingControl != nil {
				_ = c.abandonPaging(searchReq)
			}
			return fmt.Errorf("ldap search failed: %w", err)
		}

		// Process current page
		if err := handler(result.Entries); err != nil {
			if pagingControl != nil {
				_ = c.abandonPaging(searchReq)
			}
			return err
		}

		// Stop if paging not enabled
		if pagingControl == nil {
			break
		}

		// 3. Check paging response
		pagingResult := ldap.FindControl(result.Controls, analyze.OIDControlTypePaging)
		if pagingResult == nil {
			break
		}

		cookie := pagingResult.(*ldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			break
		}

		// 4. Prepare next page request
		pagingControl.SetCookie(cookie)
	}

	return nil
}

// abandonPaging attempts to notify server to abandon current paging search context
func (c *ldapClient) abandonPaging(req *ldap.SearchRequest) error {
	if len(req.Controls) == 0 {
		return nil
	}

	control := req.Controls[0].(*ldap.ControlPaging)
	control.SetCookie([]byte{})

	abandonReq := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{},
		[]ldap.Control{control},
	)
	_, err := c.conn.Search(abandonReq)
	return err
}
