package queries

import (
	"adgo/analyze"
	"fmt"
)

// certificateQueries contains AD Certificate Services (AD CS) related queries
var certificateQueries = map[string]Query{
	"caComputer": {
		Filter:     fmt.Sprintf("(&(%s=pKIEnrollmentService))", analyze.AttrObjectCategory),
		Attributes: []string{analyze.AttrCN},
	},
	"esc1": {
		Filter: fmt.Sprintf("(&(%s=pkicertificatetemplate)(!(mspki-enrollment-flag:%s:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:%s:=1)(!(cn=OfflineRouter))(!(cn=CA))(!(cn=SubCA)))",
			analyze.AttrObjectClass,
			analyze.OIDMatchRuleBitAnd,
			analyze.OIDMatchRuleBitAnd,
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
}
