package analyze

// Default Values
// These constants define the default values used throughout the application.
// They can be overridden by configuration files or command-line flags.
const (
	// LDAP Defaults
	DefaultLDAPPort         = 389   // Standard LDAP port
	DefaultLDAPSecurity     = 0     // SecurityModeNone - no encryption
	DefaultLoginName        = "userPrincipalName" // Default login name format
	DefaultConnectionTimeout = 30   // Connection timeout in seconds
	DefaultSearchTimeout    = 30    // Search timeout in seconds (prevents indefinite blocking)

	// Retry Defaults
	DefaultRetryMaxAttempts = 3          // Maximum retry attempts
	DefaultRetryInitialDelay = 100       // Initial retry delay in milliseconds
	DefaultRetryMaxDelay = 5             // Maximum retry delay in seconds
	DefaultRetryMultiplier = 2.0         // Exponential backoff multiplier

	// Output Defaults
	DefaultOutputFormat = OutputFormatText // Text output by default

	// Pagination Defaults
	DefaultPagingSize = 1000 // LDAP pagination size
)
