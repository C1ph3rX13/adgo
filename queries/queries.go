package queries

import (
	"adgo/analyze"
	"fmt"
	"sort"
	"strings"
)

// Query defines LDAP query filter and return attributes
type Query struct {
	Filter     string   // LDAP filter condition
	Attributes []string // List of attributes to return
}

// Registry manages all available queries
type Registry struct {
	queries map[string]Query
}

// Global registry instance
var registry = &Registry{
	queries: make(map[string]Query),
}

// init initializes the registry with default queries
func init() {
	// Register quick queries
	for name, q := range defaultQuickQueries {
		Register(name, q)
	}

	// Register permission queries
	for name, q := range defaultPermissionQueries {
		Register(name, q)
	}
}

// Register adds a new query to the registry
func Register(name string, q Query) {
	registry.queries[name] = q
}

// Get retrieves a query by name
func Get(name string) (Query, bool) {
	q, ok := registry.queries[name]
	return q, ok
}

// GetNames returns a sorted list of all registered query names
func GetNames() []string {
	names := make([]string, 0, len(registry.queries))
	for name := range registry.queries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// QueryBuilder constructs dynamic queries with parameter substitution
type QueryBuilder struct {
	baseQuery Query
	params    map[string]string
}

// NewQueryBuilder creates a new builder from a base query
func NewQueryBuilder(q Query) *QueryBuilder {
	return &QueryBuilder{
		baseQuery: q,
		params:    make(map[string]string),
	}
}

// defaultQuickQueries contains standard LDAP object queries
var defaultQuickQueries = map[string]Query{
	"users": {
		Filter: fmt.Sprintf("(%s=user)", analyze.AttrObjectClass),
		Attributes: []string{
			analyze.AttrSAMAccountName,
			analyze.AttrUserPrincipalName,
			analyze.AttrUserAccountControl,
			analyze.AttrMSDSAllowedToDelegateTo,
			analyze.AttrMSDSAllowedToActOnBehalfOfOtherIdentity,
		},
	},
	"computers": {
		Filter: fmt.Sprintf("(%s=computer)", analyze.AttrObjectClass),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrOperatingSystem,
			analyze.AttrDNSHostName,
			analyze.AttrUserAccountControl,
			analyze.AttrMSDSAllowedToDelegateTo,
			analyze.AttrMSDSAllowedToActOnBehalfOfOtherIdentity,
		},
	},
	"dc": {
		Filter: fmt.Sprintf("(&(%s=computer)(%s:%s:=%d))",
			analyze.AttrObjectClass,
			analyze.AttrUserAccountControl,
			analyze.OIDMatchRuleBitOr,
			analyze.UACDomainController,
		),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrOperatingSystem,
			analyze.AttrDNSHostName,
			analyze.AttrUserAccountControl,
			analyze.AttrMSDSAllowedToDelegateTo,
			analyze.AttrMSDSAllowedToActOnBehalfOfOtherIdentity,
		},
	},
	"ou": {
		Filter: fmt.Sprintf("(%s=organizationalUnit)", analyze.AttrObjectClass),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrDistinguishedName,
		},
	},
	"spn": {
		Filter: fmt.Sprintf("(&(%s=*))", analyze.AttrServicePrincipalName),
		Attributes: []string{
			"dn", // dn is not an attribute but often used in LDAP libs, keeping as is
			analyze.AttrCN,
			analyze.AttrServicePrincipalName,
		},
	},
	"adminSDHolder": {
		Filter: fmt.Sprintf("(&(%s=person)(%s=*)(%s=1))",
			analyze.AttrObjectCategory,
			analyze.AttrSAMAccountName,
			analyze.AttrAdminCount,
		),
		Attributes: []string{
			analyze.AttrCN,
			analyze.AttrSAMAccountName,
		},
	},
	"group": {
		Filter: fmt.Sprintf("(&(%s=group)(%s=1))",
			analyze.AttrObjectCategory,
			analyze.AttrAdminCount,
		),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrMember,
			analyze.AttrMemberOf,
			analyze.AttrGroupType,
		},
	},
	"disabled": {
		Filter: fmt.Sprintf("(%s:%s:=%d)",
			analyze.AttrUserAccountControl,
			analyze.OIDMatchRuleBitOr,
			analyze.UACAccountDisable,
		),
		Attributes: []string{
			"dn",
			analyze.AttrSAMAccountName,
			analyze.AttrUserPrincipalName,
			analyze.AttrLastLogonTimestamp,
		},
	},
	"admin": {
		Filter: fmt.Sprintf("(&(|(&(%s=person)(%s=user))(%s=group))(%s=1))",
			analyze.AttrObjectCategory,
			analyze.AttrObjectClass,
			analyze.AttrObjectCategory,
			analyze.AttrAdminCount,
		),
		Attributes: []string{
			"dn",
			analyze.AttrCN,
			analyze.AttrMember,
		},
	},
	"enterprise": {
		Filter: fmt.Sprintf("(%s=Enterprise Admins)", analyze.AttrSAMAccountName),
		Attributes: []string{
			"dn",
			analyze.AttrCN,
			analyze.AttrMember,
		},
	},
	"trustDomain": {
		Filter: fmt.Sprintf("(%s=trustedDomain)", analyze.AttrObjectClass),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrTrustDirection,
			analyze.AttrTrustType,
			analyze.AttrTrustAttributes,
			analyze.AttrFlatName,
			analyze.AttrDistinguishedName,
		},
	},
	"trustattributes": {
		Filter: fmt.Sprintf("(&(%s=trustedDomain)(%s=*))",
			analyze.AttrObjectClass,
			analyze.AttrTrustAttributes,
		),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrTrustAttributes,
			analyze.AttrTrustDirection,
			analyze.AttrTrustType,
		},
	},
	"sidhistory": {
		Filter: fmt.Sprintf("(%s=*)", analyze.AttrSIDHistory),
		Attributes: []string{
			"dn",
			analyze.AttrCN,
			analyze.AttrSAMAccountName,
			analyze.AttrSIDHistory,
		},
	},
	"gpo": {
		Filter: fmt.Sprintf("(%s=groupPolicyContainer)", analyze.AttrObjectClass),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrDisplayName,
			analyze.AttrVersionNumber,
			analyze.AttrGPCFileSysPath,
			analyze.AttrWhenChanged,
		},
	},
	"gpomachine": {
		Filter: fmt.Sprintf("(&(%s=groupPolicyContainer)(%s=*))",
			analyze.AttrObjectCategory,
			analyze.AttrGPCMachineExtensionNames,
		),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrDisplayName,
			analyze.AttrGPCMachineExtensionNames,
		},
	},
	"gpouser": {
		Filter: fmt.Sprintf("(&(%s=groupPolicyContainer)(%s=*))",
			analyze.AttrObjectCategory,
			analyze.AttrGPCUserExtensionNames,
		),
		Attributes: []string{
			analyze.AttrName,
			analyze.AttrDisplayName,
			analyze.AttrGPCUserExtensionNames,
		},
	},
	// Password Attacks
	"asreproast": {
		Filter: fmt.Sprintf("(&(%s:%s:=%d)(!(%s:%s:=%d))(!(%s=computer)))",
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UACDontRequirePreauth,
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UACAccountDisable,
			analyze.AttrObjectCategory,
		),
		Attributes: []string{"dn", analyze.AttrSAMAccountName},
	},
	"kerberoasting": {
		Filter: fmt.Sprintf("(&(!(%s:%s:=%d))(samAccountType=805306368)(%s=*)(!%s=krbtgt))",
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UACAccountDisable,
			analyze.AttrServicePrincipalName,
			analyze.AttrSAMAccountName,
		),
		Attributes: []string{"dn", analyze.AttrSAMAccountName, analyze.AttrServicePrincipalName},
	},
	// Delegation
	"delegate": {
		Filter: fmt.Sprintf("(%s=*)", analyze.AttrMSDSAllowedToDelegateTo),
		Attributes: []string{
			"dn",
			analyze.AttrCN,
			analyze.AttrSAMAccountName,
			analyze.AttrMSDSAllowedToDelegateTo,
		},
	},
	"unconstraineddelegate": {
		Filter: fmt.Sprintf("(%s:%s:=%d)",
			analyze.AttrUserAccountControl,
			analyze.OIDMatchRuleBitOr,
			analyze.UACTrustedForDelegation,
		),
		Attributes: []string{
			"dn",
			analyze.AttrCN,
			analyze.AttrSAMAccountName,
			analyze.AttrUserAccountControl,
			analyze.AttrObjectClass,
		},
	},
	"constraineddelegate": {
		Filter: fmt.Sprintf("(%s=*)", analyze.AttrMSDSAllowedToDelegateTo),
		Attributes: []string{
			"dn",
			analyze.AttrCN,
			analyze.AttrSAMAccountName,
			analyze.AttrMSDSAllowedToDelegateTo,
			analyze.AttrObjectClass,
		},
	},
	"resourceconstraineddelegate": {
		Filter: fmt.Sprintf("(%s=*)", analyze.AttrMSDSAllowedToActOnBehalfOfOtherIdentity),
		Attributes: []string{
			"dn",
			analyze.AttrCN,
			analyze.AttrSAMAccountName,
			analyze.AttrMSDSAllowedToActOnBehalfOfOtherIdentity,
			analyze.AttrObjectClass,
		},
	},
	// Certificates (AD CS)
	"caComputer": {
		Filter:     fmt.Sprintf("(&(%s=pKIEnrollmentService))", analyze.AttrObjectCategory),
		Attributes: []string{analyze.AttrCN},
	},
	"esc1": {
		Filter: fmt.Sprintf("(&(%s=pkicertificatetemplate)(!(mspki-enrollment-flag:%s:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:%s:=1)(!(cn=OfflineRouter))(!(cn=CA))(!(cn=SubCA)))",
			analyze.AttrObjectClass,
			analyze.OIDMatchRuleBitAnd, // 1.2.840.113556.1.4.804
			analyze.OIDMatchRuleBitAnd, // 1.2.840.113556.1.4.804
		),
		Attributes: []string{analyze.AttrCN},
	},
	"esc2": {
		Filter: fmt.Sprintf("(&(%s=pkicertificatetemplate)(!(mspki-enrollment-flag:%s:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(!(cn=CA))(!(cn=SubCA)))",
			analyze.AttrObjectClass,
			analyze.OIDMatchRuleBitAnd,
		),
		Attributes: []string{analyze.AttrCN},
	},
	"machineAccountQuota": {
		Filter:     "(objectClass=domain)",
		Attributes: []string{"ms-DS-MachineAccountQuota"},
	},
}

// defaultPermissionQueries contains permission related queries
var defaultPermissionQueries = map[string]Query{
	"permissions": {
		Filter: fmt.Sprintf("(&(%s=user)(%s=*))",
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
		),
		Attributes: []string{
			analyze.AttrSAMAccountName,
			analyze.AttrUserPrincipalName,
			analyze.AttrMemberOf,
			analyze.AttrAdminCount,
			analyze.AttrUserAccountControl,
		},
	},
	"highpriv": {
		Filter: fmt.Sprintf("(&(%s=user)(%s=1))",
			analyze.AttrObjectClass,
			analyze.AttrAdminCount,
		),
		Attributes: []string{
			analyze.AttrSAMAccountName,
			analyze.AttrUserPrincipalName,
			analyze.AttrMemberOf,
			analyze.AttrAdminCount,
			analyze.AttrUserAccountControl,
		},
	},
	"domainadmins": {
		Filter: fmt.Sprintf("(&(%s=group)(%s=Domain Admins))",
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
		),
		Attributes: []string{
			analyze.AttrMember,
			analyze.AttrDistinguishedName,
			analyze.AttrGroupType,
		},
	},
	"enterpriseadmins": {
		Filter: fmt.Sprintf("(&(%s=group)(%s=Enterprise Admins))",
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
		),
		Attributes: []string{
			analyze.AttrMember,
			analyze.AttrDistinguishedName,
			analyze.AttrGroupType,
		},
	},
	"schemaadmins": {
		Filter: fmt.Sprintf("(&(%s=group)(%s=Schema Admins))",
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
		),
		Attributes: []string{
			analyze.AttrMember,
			analyze.AttrDistinguishedName,
			analyze.AttrGroupType,
		},
	},
	"adminholders": {
		Filter: fmt.Sprintf("(&(%s=person)(%s=*)(%s=1))",
			analyze.AttrObjectCategory,
			analyze.AttrSAMAccountName,
			analyze.AttrAdminCount,
		),
		Attributes: []string{
			analyze.AttrSAMAccountName,
			analyze.AttrDistinguishedName,
			analyze.AttrMemberOf,
			analyze.AttrAdminCount,
		},
	},
	"groupnested": {
		Filter: fmt.Sprintf("(&(%s=group)(%s=*))",
			analyze.AttrObjectClass,
			analyze.AttrMember,
		),
		Attributes: []string{
			analyze.AttrCN,
			analyze.AttrMember,
			analyze.AttrDistinguishedName,
			analyze.AttrGroupType,
		},
	},
	"sensitivegroups": {
		Filter: fmt.Sprintf("(&(%s=group)(|(%s=Domain Admins)(%s=Enterprise Admins)(%s=Schema Admins)(%s=Administrators)(%s=Domain Controllers)(%s=Enterprise Key Admins)(%s=Domain Key Admins)))",
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
			analyze.AttrSAMAccountName,
			analyze.AttrSAMAccountName,
			analyze.AttrSAMAccountName,
			analyze.AttrSAMAccountName,
			analyze.AttrSAMAccountName,
			analyze.AttrSAMAccountName,
		),
		Attributes: []string{
			analyze.AttrSAMAccountName,
			analyze.AttrMember,
			analyze.AttrDistinguishedName,
		},
	},
	"managedby": {
		Filter: fmt.Sprintf("(&(%s=*))", analyze.AttrManagedBy),
		Attributes: []string{
			analyze.AttrCN,
			analyze.AttrDistinguishedName,
			analyze.AttrManagedBy,
		},
	},
	"acl": {
		Filter: fmt.Sprintf("(&(%s=*)(%s=*))",
			analyze.AttrObjectClass,
			analyze.AttrNTSecurityDescriptor,
		),
		Attributes: []string{
			analyze.AttrCN,
			analyze.AttrDistinguishedName,
			analyze.AttrNTSecurityDescriptor,
		},
	},
}

// DomainSpecificQueries requires domain name parameter
var DomainSpecificQueries = map[string]Query{
	"dcclonerights": {
		Filter: fmt.Sprintf("(&(%s=user)(|(%s:%s:=%d)(%s:%s:=CN=Cloneable Domain Controllers,CN=Users,{domain})))",
			analyze.AttrObjectClass,
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UACEncryptedTextPasswordAllowed,
			analyze.AttrMemberOf, analyze.OIDMatchRuleInChain,
		),
		Attributes: []string{"dn", analyze.AttrCN, analyze.AttrSAMAccountName, analyze.AttrMemberOf},
	},
	"dcsync": {
		Filter: fmt.Sprintf("(&(%s=user)(|(%s:%s:=CN=Domain Admins,CN=Users,{domain})(%s:%s:=CN=Enterprise Admins,CN=Users,{domain})(%s:%s:=CN=Administrators,CN=Builtin,{domain})))",
			analyze.AttrObjectClass,
			analyze.AttrMemberOf, analyze.OIDMatchRuleInChain,
			analyze.AttrMemberOf, analyze.OIDMatchRuleInChain,
			analyze.AttrMemberOf, analyze.OIDMatchRuleInChain,
		),
		Attributes: []string{"dn", analyze.AttrCN, analyze.AttrSAMAccountName, analyze.AttrMemberOf},
	},
}

// WithParam sets a parameter for replacement
func (b *QueryBuilder) WithParam(key, value string) *QueryBuilder {
	b.params[key] = value
	return b
}

// WithAttributes sets custom return attributes
func (b *QueryBuilder) WithAttributes(attributes ...string) *QueryBuilder {
	if len(attributes) > 0 {
		b.baseQuery.Attributes = attributes
	}
	return b
}

// WithBaseDN sets the baseDN parameter
func (b *QueryBuilder) WithBaseDN(baseDN string) *QueryBuilder {
	b.params["baseDN"] = baseDN
	return b
}

// Build constructs the final query object
func (b *QueryBuilder) Build() Query {
	result := Query{
		Filter:     b.replaceParams(b.baseQuery.Filter),
		Attributes: make([]string, len(b.baseQuery.Attributes)),
	}

	copy(result.Attributes, b.baseQuery.Attributes)
	return result
}

// replaceParams replaces placeholders with parameter values
func (b *QueryBuilder) replaceParams(filter string) string {
	result := filter
	for key, value := range b.params {
		placeholder := "{" + key + "}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}
