package connect

import (
	"fmt"
	"strings"
)

// ErrorWithHelp provides structured error information with diagnosis and solutions
type ErrorWithHelp struct {
	Err       error
	Diagnosis string
	Solutions []string
	Details   map[string]string
}

func (e *ErrorWithHelp) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[ERROR] %v\n", e.Err))

	if e.Diagnosis != "" {
		sb.WriteString(fmt.Sprintf("\n[DIAGNOSIS] %s\n", e.Diagnosis))
	}

	if len(e.Details) > 0 {
		sb.WriteString("\n[DETAILS]\n")
		for k, v := range e.Details {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}

	if len(e.Solutions) > 0 {
		sb.WriteString("\n[SUGGESTED FIXES]\n")
		for i, sol := range e.Solutions {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, sol))
		}
	}

	return sb.String()
}

func (e *ErrorWithHelp) Unwrap() error {
	return e.Err
}

// NewDiagnosticError creates a new error with diagnostic information
func NewDiagnosticError(err error, diagnosis string, solutions []string) error {
	return &ErrorWithHelp{
		Err:       err,
		Diagnosis: diagnosis,
		Solutions: solutions,
	}
}

// NewDetailedDiagnosticError creates a new error with diagnostics and additional details
func NewDetailedDiagnosticError(err error, diagnosis string, solutions []string, details map[string]string) error {
	return &ErrorWithHelp{
		Err:       err,
		Diagnosis: diagnosis,
		Solutions: solutions,
		Details:   details,
	}
}

// AnalyzeConnectionError analyzes connection errors and provides helpful suggestions
func AnalyzeConnectionError(server string, err error) error {
	errStr := strings.ToLower(err.Error())

	var diagnosis string
	var solutions []string

	// Connection refused
	if strings.Contains(errStr, "connection refused") {
		diagnosis = "The LDAP server refused the connection"
		solutions = []string{
			fmt.Sprintf("Verify the server address '%s' is correct", server),
			"Check if the LDAP service is running on the target",
			"Verify network connectivity to the server",
			"Check firewall rules allow connections to the LDAP port",
			"Try using ldaps:// (port 636) instead of ldap:// (port 389)",
		}
	} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout") {
		diagnosis = "Connection attempt timed out"
		solutions = []string{
			"Check network connectivity to the server",
			"Verify the server is responsive",
			"Check if a firewall is blocking the connection",
			"Try increasing the connection timeout with --timeout flag",
			"Test basic connectivity with ping or telnet",
		}
	} else if strings.Contains(errStr, "no route to host") || strings.Contains(errStr, "network is unreachable") {
		diagnosis = "Network route to the host is not available"
		solutions = []string{
			"Check your network connection",
			"Verify the server address is correct",
			"Check if VPN is required to reach the network",
			"Verify routing table and gateway configuration",
		}
	} else if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
		diagnosis = "TLS handshake or certificate error"
		solutions = []string{
			"Try using security mode 3 (InsecureTLS) to bypass certificate validation",
			"Verify the server's certificate is valid",
			"Check if the server name matches the certificate",
			"Ensure the certificate chain is properly configured",
		}
	} else {
		diagnosis = "Failed to connect to LDAP server"
		solutions = []string{
			"Verify the server address and port are correct",
			"Check if the LDAP service is running",
			"Test network connectivity",
			"Review firewall and network security policies",
		}
	}

	return &ErrorWithHelp{
		Err:       err,
		Diagnosis: diagnosis,
		Solutions: solutions,
		Details: map[string]string{
			"server": server,
		},
	}
}

// AnalyzeBindError analyzes bind/authentication errors
func AnalyzeBindError(username string, err error) error {
	errStr := strings.ToLower(err.Error())

	var diagnosis string
	var solutions []string

	if strings.Contains(errStr, "invalid credentials") || strings.Contains(errStr, "invalid dn") {
		diagnosis = "Authentication failed - invalid credentials"
		solutions = []string{
			"Verify the username is correct",
			"Check if the password is correct",
			"Ensure the account is not locked or disabled",
			"Try using --login-name flag to switch between sAMAccountName and userPrincipalName",
			"Verify the account has permission to bind to the LDAP server",
		}
	} else if strings.Contains(errStr, "password") || strings.Contains(errStr, "credential") {
		diagnosis = "Credential validation failed"
		solutions = []string{
			"Double-check the password",
			"Ensure the password doesn't contain special characters that need escaping",
			"Try a different account to verify the issue is account-specific",
		}
	} else if strings.Contains(errStr, "timeout") {
		diagnosis = "Bind operation timed out"
		solutions = []string{
			"Check if the LDAP server is under heavy load",
			"Verify network stability",
			"Try increasing the timeout value",
		}
	} else {
		diagnosis = "Failed to authenticate to LDAP server"
		solutions = []string{
			"Verify credentials are correct",
			"Check if the account is active and not locked",
			"Try using --login-name flag to switch between sAMAccountName and userPrincipalName",
			"Verify the account has LDAP bind permissions",
		}
	}

	return &ErrorWithHelp{
		Err:       err,
		Diagnosis: diagnosis,
		Solutions: solutions,
		Details: map[string]string{
			"username": username,
		},
	}
}

// AnalyzeSearchError analyzes LDAP search errors
func AnalyzeSearchError(baseDN string, filter string, err error) error {
	errStr := strings.ToLower(err.Error())

	var diagnosis string
	var solutions []string

	if strings.Contains(errStr, "size limit exceeded") {
		diagnosis = "Search returned more results than the size limit allows"
		solutions = []string{
			"Use --size-limit flag to increase or remove the size limit",
			"Narrow your search filter to be more specific",
			"Consider using pagination to retrieve results in batches",
		}
	} else if strings.Contains(errStr, "time limit exceeded") {
		diagnosis = "Search took too long and exceeded the time limit"
		solutions = []string{
			"Narrow your search filter to reduce processing time",
			"Check if the LDAP server is under heavy load",
			"Try searching a smaller subset of the directory",
		}
	} else if strings.Contains(errStr, "no such object") || strings.Contains(errStr, "invalid dn") {
		diagnosis = "The specified Base DN does not exist"
		solutions = []string{
			"Verify the Base DN is correct (e.g., DC=domain,DC=com)",
			"Use a tool like ldapsearch to verify the Base DN exists",
			"Check if you have permission to search this Base DN",
			"Ensure the domain name is spelled correctly",
		}
	} else if strings.Contains(errStr, "insufficient access") || strings.Contains(errStr, "unauthorized") {
		diagnosis = "You don't have permission to perform this search"
		solutions = []string{
			"Verify your account has permission to search the specified attributes",
			"Try searching with fewer attributes",
			"Check if the search filter requires elevated privileges",
			"Contact your domain administrator if permissions appear incorrect",
		}
	} else if strings.Contains(errStr, "filter") || strings.Contains(errStr, "syntax") {
		diagnosis = "The search filter contains a syntax error"
		solutions = []string{
			"Verify the LDAP filter syntax is correct",
			"Ensure all parentheses are balanced",
			"Check for proper escaping of special characters",
			"Try the filter with a simpler query first",
		}
	} else {
		diagnosis = "LDAP search operation failed"
		solutions = []string{
			"Verify the Base DN is correct",
			"Check the search filter syntax",
			"Ensure you have permissions to search",
			"Verify the LDAP server is functioning properly",
		}
	}

	return &ErrorWithHelp{
		Err:       err,
		Diagnosis: diagnosis,
		Solutions: solutions,
		Details: map[string]string{
			"baseDN": baseDN,
			"filter": truncateDisplay(filter, 50),
		},
	}
}

// truncateDisplay truncates a string for display in error messages
func truncateDisplay(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
