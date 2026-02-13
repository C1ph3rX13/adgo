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

// init initializes the registry with all default queries
func init() {
	// Register basic object queries
	for name, q := range basicQueries {
		Register(name, q)
	}

	// Register privilege and group queries
	for name, q := range privilegeQueries {
		Register(name, q)
	}

	// Register Kerberos attack queries
	for name, q := range kerberosQueries {
		Register(name, q)
	}

	// Register delegation queries
	for name, q := range delegationQueries {
		Register(name, q)
	}

	// Register certificate queries
	for name, q := range certificateQueries {
		Register(name, q)
	}

	// Register domain-specific queries
	for name, q := range DomainSpecificQueries {
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

// WithBaseDN sets baseDN parameter
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

// DomainSpecificQueries requires domain name parameter
var DomainSpecificQueries = map[string]Query{
	"dcclonerights": {
		Filter: fmt.Sprintf("(&(%s=user)(|(%s:%s:=%d)(%s:%s:=CN=Cloneable Domain Controllers,CN=Users,{domain})))",
			analyze.AttrObjectClass,
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
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
