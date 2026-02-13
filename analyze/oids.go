package analyze

// LDAP Matching Rules and Control OIDs
// These constants define LDAP Object Identifiers (OIDs) for matching rules and controls.
// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
const (
	// LDAP Matching Rule OIDs
	// These OIDs define bitwise matching rules for LDAP filters
	OIDMatchRuleBitOr   = "1.2.840.113556.1.4.803"  // LDAP_MATCHING_RULE_BIT_OR
	OIDMatchRuleBitAnd  = "1.2.840.113556.1.4.804"  // LDAP_MATCHING_RULE_BIT_AND
	OIDMatchRuleInChain = "1.2.840.113556.1.4.1941" // LDAP_MATCHING_RULE_IN_CHAIN

	// LDAP Control OIDs
	// These OIDs define LDAP extended operations and controls
	OIDControlTypePaging = "1.2.840.113556.1.4.319" // LDAP_PAGED_RESULT
)
