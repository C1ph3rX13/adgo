package connect

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"adgo/analyze"

	"github.com/go-ldap/ldap/v3"
)

// ConnPool manages a pool of reusable LDAP connections
type ConnPool struct {
	conns    chan *ldap.Conn
	config    *Config
	factory   func() (*ldap.Conn, error)
	mu        sync.RWMutex
	closed    int32 // atomic
	connCount int32 // atomic
	maxSize   int
}

// PoolConfig defines connection pool configuration
type PoolConfig struct {
	MaxConns     int           // Maximum number of connections in the pool
	IdleTimeout  time.Duration // Idle timeout for connections
	MaxLifetime  time.Duration // Maximum lifetime of a connection
}

// DefaultPoolConfig returns default pool configuration
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:    5,  // 5 connections by default
		IdleTimeout:  5 * time.Minute,
		MaxLifetime: 30 * time.Minute,
	}
}

// NewConnPool creates a new connection pool
func NewConnPool(config *Config, poolCfg PoolConfig) (*ConnPool, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if poolCfg.MaxConns <= 0 {
		poolCfg.MaxConns = 5
	}

	pool := &ConnPool{
		conns:   make(chan *ldap.Conn, poolCfg.MaxConns),
		config:   config,
		maxSize:  poolCfg.MaxConns,
	}

	// Create factory function
	pool.factory = func() (*ldap.Conn, error) {
		return ldapBind(config)
	}

	// Pre-create half of the connections
	initialConns := poolCfg.MaxConns / 2
	if initialConns < 1 {
		initialConns = 1
	}

	for i := 0; i < initialConns; i++ {
		conn, err := pool.factory()
		if err != nil {
			// Log warning but continue
			continue
		}
		pool.conns <- conn
		atomic.AddInt32(&pool.connCount, 1)
	}

	return pool, nil
}

// Get retrieves a connection from the pool, or creates a new one if pool is empty
func (p *ConnPool) Get(ctx context.Context) (*ldap.Conn, error) {
	// Check if pool is closed
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, fmt.Errorf("connection pool is closed")
	}

	select {
	case conn := <-p.conns:
		// Verify connection is still alive
		if p.isAlive(conn) {
			return conn, nil
		}
		// Connection is dead, close it
		_ = conn.Close()
		atomic.AddInt32(&p.connCount, -1)

		// Fall through to create new connection
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Pool is empty, check if we can create a new connection
		if atomic.LoadInt32(&p.connCount) >= int32(p.maxSize) {
			// Wait for a connection to become available
			select {
			case conn := <-p.conns:
				if p.isAlive(conn) {
					return conn, nil
				}
				_ = conn.Close()
				atomic.AddInt32(&p.connCount, -1)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	// Create a new connection
	conn, err := p.factory()
	if err != nil {
		return nil, fmt.Errorf("creating new connection: %w", err)
	}

	atomic.AddInt32(&p.connCount, 1)
	return conn, nil
}

// Put returns a connection to the pool
func (p *ConnPool) Put(conn *ldap.Conn) error {
	if conn == nil {
		return nil
	}

	// Check if pool is closed
	if atomic.LoadInt32(&p.closed) == 1 {
		// Pool is closed, just close the connection
		return conn.Close()
	}

	select {
	case p.conns <- conn:
		// Successfully returned to pool
		return nil
	default:
		// Pool is full, close the connection
		atomic.AddInt32(&p.connCount, -1)
		return conn.Close()
	}
}

// Close closes all connections in the pool and prevents new connections from being created
func (p *ConnPool) Close() error {
	// Mark pool as closed
	if !atomic.CompareAndSwapInt32(&p.closed, 0, 1) {
		return nil // Already closed
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Close all connections in the channel
	close(p.conns)
	for conn := range p.conns {
		if conn != nil {
			_ = conn.Close()
			atomic.AddInt32(&p.connCount, -1)
		}
	}

	return nil
}

// Size returns the current number of connections in the pool
func (p *ConnPool) Size() int {
	return len(p.conns)
}

// Count returns the total number of connections created (includes those in use)
func (p *ConnPool) Count() int {
	return int(atomic.LoadInt32(&p.connCount))
}

// isAlive checks if a connection is still alive by performing a simple ping
func (p *ConnPool) isAlive(conn *ldap.Conn) bool {
	if conn == nil {
		return false
	}

	// Simple check - try to read from the connection with a short timeout
	// If connection is dead, this will fail quickly
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Try a root DSE query
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		1,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	// Use context - check if Search can be done with ctx
	// Note: ldap.Conn doesn't have SearchWithTimeout, so we use Search directly
	// The context timeout handles the timing
	doneChan := make(chan error, 1)
	go func() {
		_, err := conn.Search(req)
		doneChan <- err
	}()

	select {
	case err := <-doneChan:
		return err == nil
	case <-ctx.Done():
		return false
	}
}

// PoolingClient wraps a connection pool and implements the Client interface
type PoolingClient struct {
	pool   *ConnPool
	config *Config
}

// NewPoolingClient creates a new client that uses connection pooling
func NewPoolingClient(config *Config, poolCfg PoolConfig) (Client, error) {
	pool, err := NewConnPool(config, poolCfg)
	if err != nil {
		return nil, err
	}

	return &PoolingClient{
		pool:   pool,
		config: config,
	}, nil
}

// Search executes a search using a connection from the pool
func (pc *PoolingClient) Search(ctx context.Context, filter string, attributes []string) ([]*ldap.Entry, error) {
	// Get connection from pool
	conn, err := pc.pool.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting connection from pool: %w", err)
	}

	// Ensure connection is returned to pool
	defer func() {
		_ = pc.pool.Put(conn)
	}()

	// Perform search using the connection
	return pc.searchWithConn(ctx, conn, filter, attributes)
}

// StreamSearch executes a streaming search using a connection from the pool
func (pc *PoolingClient) StreamSearch(ctx context.Context, filter string, attributes []string) (<-chan *ldap.Entry, <-chan error) {
	// Get connection from pool
	conn, err := pc.pool.Get(ctx)
	if err != nil {
		errChan := make(chan error, 1)
		errChan <- err
		close(errChan)
		return make(chan *ldap.Entry), errChan
	}

	entriesChan := make(chan *ldap.Entry, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(entriesChan)
		defer close(errChan)
		defer pc.pool.Put(conn)

		// Perform streaming search
		entries, err := pc.searchWithConn(ctx, conn, filter, attributes)
		if err != nil {
			errChan <- err
			return
		}

		for _, entry := range entries {
			select {
			case entriesChan <- entry:
			case <-ctx.Done():
				return
			}
		}
	}()

	return entriesChan, errChan
}

// Ping checks if a connection can be established
func (pc *PoolingClient) Ping(ctx context.Context) error {
	conn, err := pc.pool.Get(ctx)
	if err != nil {
		return err
	}
	defer pc.pool.Put(conn)

	// Simple root DSE query
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		1,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	// Use Search directly with timeout context
	_, err = conn.Search(req)
	return err
}

// Close closes the connection pool
func (pc *PoolingClient) Close() error {
	return pc.pool.Close()
}

// searchWithConn performs a search using a specific connection
func (pc *PoolingClient) searchWithConn(ctx context.Context, conn *ldap.Conn, filter string, attributes []string) ([]*ldap.Entry, error) {
	searchReq := ldap.NewSearchRequest(
		pc.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // SizeLimit: set from config
		0, // TimeLimit: set from config
		false,
		filter,
		attributes,
		nil, // Controls
	)

	// Apply size limit from config
	if pc.config.SizeLimit > 0 {
		searchReq.SizeLimit = pc.config.SizeLimit
	}

	// Add paging control
	pagingControl := ldap.NewControlPaging(uint32(analyze.DefaultPagingSize))
	searchReq.Controls = []ldap.Control{pagingControl}

	var allEntries []*ldap.Entry

	for {
		// Execute search with context
		sr, err := conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("ldap search failed: %w", err)
		}

		// Append entries
		allEntries = append(allEntries, sr.Entries...)

		// Check if there are more pages
		pagingResult := ldap.FindControl(sr.Controls, analyze.OIDControlTypePaging)
		if pagingResult == nil {
			break
		}

		pagingControlResult, ok := pagingResult.(*ldap.ControlPaging)
		if !ok {
			return nil, fmt.Errorf("unexpected control type returned for paging")
		}

		cookie := pagingControlResult.Cookie
		if len(cookie) == 0 {
			break
		}

		// Set cookie for next page
		pagingControl.SetCookie(cookie)
	}

	return allEntries, nil
}
