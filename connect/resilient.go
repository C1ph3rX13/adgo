package connect

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ResilientClient wraps a Client with retry and resilience capabilities
type ResilientClient struct {
	client   Client
	retryCfg RetryConfig
	mu       sync.RWMutex
	onRetry  func(attempt int, err error)
	onFailure func(error)
}

// NewResilientClient creates a new resilient client wrapper
func NewResilientClient(client Client, retryCfg RetryConfig) *ResilientClient {
	if retryCfg.MaxAttempts <= 0 {
		retryCfg.MaxAttempts = 3 // Default from retry.go
	}
	if retryCfg.InitialDelay <= 0 {
		retryCfg.InitialDelay = time.Duration(100) * time.Millisecond
	}
	if retryCfg.MaxDelay <= 0 {
		retryCfg.MaxDelay = time.Duration(5) * time.Second
	}
	if retryCfg.Multiplier <= 1.0 {
		retryCfg.Multiplier = 2.0
	}

	return &ResilientClient{
		client:   client,
		retryCfg: retryCfg,
	}
}

// SetRetryCallback sets a callback function that is called on each retry attempt
func (rc *ResilientClient) SetRetryCallback(fn func(attempt int, err error)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.onRetry = fn
}

// SetFailureCallback sets a callback function that is called after all retries are exhausted
func (rc *ResilientClient) SetFailureCallback(fn func(error)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.onFailure = fn
}

// Search executes a search with retry capability
func (rc *ResilientClient) Search(ctx context.Context, filter string, attributes []string) ([]*ldap.Entry, error) {
	var lastErr error

	for attempt := 0; attempt < rc.retryCfg.MaxAttempts; attempt++ {
		// Skip delay for first attempt
		if attempt > 0 {
			delay := rc.calculateBackoff(attempt)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Attempt search
		entries, err := rc.client.Search(ctx, filter, attributes)
		if err == nil {
			return entries, nil
		}

		lastErr = err

		// Check if error is retryable
		if !IsRetryableError(err) && !isTemporaryError(err) {
			// Non-retryable error, return immediately
			break
		}

		// Call retry callback if set
		rc.mu.RLock()
		onRetry := rc.onRetry
		rc.mu.RUnlock()

		if onRetry != nil {
			onRetry(attempt+1, err)
		}

		// Try to reconnect if this is a connection-related error
		if isConnectionError(err) {
			if connErr := rc.reconnect(ctx); connErr != nil {
				// Reconnect failed, but continue trying
				continue
			}
		}
	}

	// All retries exhausted
	rc.mu.RLock()
	onFailure := rc.onFailure
	rc.mu.RUnlock()

	if onFailure != nil {
		onFailure(lastErr)
	}

	return nil, fmt.Errorf("after %d attempts: %w", rc.retryCfg.MaxAttempts, lastErr)
}

// StreamSearch executes a streaming search with retry capability
func (rc *ResilientClient) StreamSearch(ctx context.Context, filter string, attributes []string) (<-chan *ldap.Entry, <-chan error) {
	entriesChan := make(chan *ldap.Entry, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(entriesChan)
		defer close(errChan)

		var lastErr error

		for attempt := 0; attempt < rc.retryCfg.MaxAttempts; attempt++ {
			// Skip delay for first attempt
			if attempt > 0 {
				delay := rc.calculateBackoff(attempt)
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				}
			}

			// Create a sub-context for this attempt
			attemptCtx, cancel := context.WithCancel(ctx)

			// Attempt stream search
			innerEntries, innerErr := rc.client.StreamSearch(attemptCtx, filter, attributes)

			// Forward all entries and check for error
			done := false
			for !done {
				select {
				case entry, ok := <-innerEntries:
					if !ok {
						done = true
						break
					}
					select {
					case entriesChan <- entry:
					case <-ctx.Done():
						cancel()
						errChan <- ctx.Err()
						return
					}
				case err, ok := <-innerErr:
					if ok && err != nil {
						lastErr = err

						// Check if error is retryable
						if !IsRetryableError(err) && !isTemporaryError(err) {
							// Non-retryable error
							cancel()
							errChan <- err
							return
						}

						// Break to retry
						done = true
					} else {
						// Success!
						cancel()
						return
					}
				case <-ctx.Done():
					cancel()
					errChan <- ctx.Err()
					return
				}
			}

			cancel()

			// Call retry callback if set
			rc.mu.RLock()
			onRetry := rc.onRetry
			rc.mu.RUnlock()

			if onRetry != nil {
				onRetry(attempt+1, lastErr)
			}

			// Try to reconnect if this is a connection-related error
			if isConnectionError(lastErr) {
				_ = rc.reconnect(ctx)
			}
		}

		// All retries exhausted
		rc.mu.RLock()
		onFailure := rc.onFailure
		rc.mu.RUnlock()

		if onFailure != nil {
			onFailure(lastErr)
		}

		errChan <- fmt.Errorf("after %d attempts: %w", rc.retryCfg.MaxAttempts, lastErr)
	}()

	return entriesChan, errChan
}

// Ping executes a health check with retry capability
func (rc *ResilientClient) Ping(ctx context.Context) error {
	var lastErr error

	for attempt := 0; attempt < rc.retryCfg.MaxAttempts; attempt++ {
		// Skip delay for first attempt
		if attempt > 0 {
			delay := rc.calculateBackoff(attempt)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := rc.client.Ping(ctx)
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !IsRetryableError(err) && !isTemporaryError(err) {
			break
		}
	}

	return fmt.Errorf("after %d attempts: %w", rc.retryCfg.MaxAttempts, lastErr)
}

// Close closes underlying client
func (rc *ResilientClient) Close() error {
	return rc.client.Close()
}

// reconnect attempts to close and recreate underlying connection
func (rc *ResilientClient) reconnect(ctx context.Context) error {
	// Close existing connection
	_ = rc.client.Close()

	// For ldapClient, we would need to recreate connection
	// This is a limitation of current interface
	// In a future refactor, we might add a Reconnect() method to Client interface
	return fmt.Errorf("reconnect not supported")
}

// calculateBackoff calculates exponential backoff delay for a given attempt
func (rc *ResilientClient) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff with jitter
	delay := float64(rc.retryCfg.InitialDelay) * math.Pow(rc.retryCfg.Multiplier, float64(attempt-1))

	// Cap at max delay
	if delay > float64(rc.retryCfg.MaxDelay) {
		delay = float64(rc.retryCfg.MaxDelay)
	}

	// Add jitter (±25%)
	jitter := delay * 0.25 * (2.0*float64(time.Now().UnixNano()%1000)/1000.0 - 1.0)

	return time.Duration(delay + jitter)
}

// isTemporaryError checks if an error is temporary (net.Error)
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary()
	}

	return false
}

// isConnectionError checks if an error is connection-related
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Connection error patterns
	connectionPatterns := []string{
		"broken pipe",
		"connection reset",
		"use of closed network connection",
		"ldap server down",
		"connection lost",
	}

	for _, pattern := range connectionPatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}
