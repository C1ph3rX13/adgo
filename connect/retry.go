package connect

import (
	"adgo/analyze"
	"fmt"
	"math"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// RetryConfig defines the retry behavior for LDAP connections
type RetryConfig struct {
	MaxAttempts  int           // Maximum number of retry attempts
	InitialDelay time.Duration // Initial delay before first retry
	MaxDelay     time.Duration // Maximum delay between retries
	Multiplier   float64       // Multiplier for exponential backoff
}

// DefaultRetryConfig returns the default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  analyze.DefaultRetryMaxAttempts,
		InitialDelay: time.Duration(analyze.DefaultRetryInitialDelay) * time.Millisecond,
		MaxDelay:     time.Duration(analyze.DefaultRetryMaxDelay) * time.Second,
		Multiplier:   analyze.DefaultRetryMultiplier,
	}
}

// ldapBindWithRetry attempts to bind to LDAP server with exponential backoff retry
func ldapBindWithRetry(c *Config, retryCfg RetryConfig) (*ldap.Conn, error) {
	var lastErr error

	for attempt := 0; attempt < retryCfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Calculate backoff delay
			delay := calculateBackoff(attempt, retryCfg)
			fmt.Printf("Retry attempt %d/%d after %v (previous error: %v)\n",
				attempt+1, retryCfg.MaxAttempts, delay, lastErr)
			time.Sleep(delay)
		}

		// Attempt connection
		conn, err := ldapBind(c)
		if err == nil {
			if attempt > 0 {
				fmt.Printf("Connected after %d attempt(s)\n", attempt+1)
			}
			return conn, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf("failed after %d attempt(s): %w", retryCfg.MaxAttempts, lastErr)
}

// calculateBackoff calculates the delay for a given retry attempt using exponential backoff
func calculateBackoff(attempt int, cfg RetryConfig) time.Duration {
	delay := cfg.InitialDelay * time.Duration(math.Pow(cfg.Multiplier, float64(attempt)))
	if delay > cfg.MaxDelay {
		delay = cfg.MaxDelay
	}
	return delay
}

// RetryableError checks if an error is retryable
func RetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific LDAP error codes that are retryable
	if ldapErr, ok := err.(*ldap.Error); ok {
		// Network errors, timeout errors, and server unavailable are retryable
		switch ldapErr.ResultCode {
		case ldap.LDAPResultBusy:
			return true
		case ldap.LDAPResultUnavailable:
			return true
		case ldap.LDAPResultLoopDetect:
			return false // Don't retry on loop detect
		}
	}

	// Check for network-related errors
	errStr := err.Error()
	retryableErrors := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"network is unreachable",
		"no route to host",
		"i/o timeout",
	}

	for _, retryable := range retryableErrors {
		if contains(errStr, retryable) {
			return true
		}
	}

	// Default to not retryable for safety
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
		 len(s) > len(substr) && (
			s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
		 indexOfSubstring(s, substr) >= 0))
}

func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
