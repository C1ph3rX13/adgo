package queries

import (
	"adgo/analyze"
	"fmt"
)

// delegationQueries contains Kerberos delegation-related queries
var delegationQueries = map[string]Query{
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
			analyze.UF_TRUSTED_FOR_DELEGATION,
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
}
