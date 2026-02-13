package analyze

// Configuration Keys
// These constants define the configuration key paths used by the Viper configuration management system.
// They follow a hierarchical naming convention (e.g., "ldap.server", "ldap.port").
const (
	ConfigLDAPServer    = "ldap.server"
	ConfigLDAPPort      = "ldap.port"
	ConfigLDAPBaseDN    = "ldap.baseDN"
	ConfigLDAPUsername  = "ldap.username"
	ConfigLDAPPassword  = "ldap.password"
	ConfigLDAPLoginName = "ldap.loginName"
	ConfigLDAPSecurity  = "ldap.security"
	ConfigOutput        = "output"
)

// Output Formats
const (
	OutputFormatText = "text"
	OutputFormatJSON = "json"
	OutputFormatCSV  = "csv"
)

// Port Ranges
const (
	MinPort = 1
	MaxPort = 65535
)
