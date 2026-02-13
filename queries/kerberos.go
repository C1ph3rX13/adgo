package queries

import (
	"adgo/analyze"
	"fmt"
)

// kerberosQueries contains Kerberos-related attack queries
var kerberosQueries = map[string]Query{
	"asreproast": {
		Filter: fmt.Sprintf("(&(%s:%s:=%d)(!(%s:%s:=%d))(!(%s=computer)))",
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UF_DONT_REQUIRE_PREAUTH,
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UF_ACCOUNTDISABLE,
			analyze.AttrObjectCategory,
		),
		Attributes: []string{"dn", analyze.AttrSAMAccountName},
	},
	"kerberoasting": {
		Filter: fmt.Sprintf("(&(!(%s:%s:=%d))(samAccountType=805306368)(%s=*)(!%s=krbtgt))",
			analyze.AttrUserAccountControl, analyze.OIDMatchRuleBitOr, analyze.UF_ACCOUNTDISABLE,
			analyze.AttrServicePrincipalName,
			analyze.AttrSAMAccountName,
		),
		Attributes: []string{"dn", analyze.AttrSAMAccountName, analyze.AttrServicePrincipalName},
	},
}
