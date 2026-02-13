package queries

import (
	"adgo/analyze"
	"fmt"
)

// basicQueries contains standard LDAP object queries
var basicQueries = map[string]Query{
	"users": {
		Filter: fmt.Sprintf("(%s=user)", analyze.AttrObjectClass),
		Attributes: []string{
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
			analyze.AttrUserPrincipalName,
			analyze.AttrUserAccountControl,
			analyze.AttrObjectSID,
			analyze.AttrServicePrincipalName,
			analyze.AttrAdminCount,
			analyze.AttrWhenCreated,
			analyze.AttrPwdLastSet,
			analyze.AttrMSDSAllowedToDelegateTo,
			analyze.AttrMSDSAllowedToActOnBehalfOfOtherIdentity,
		},
	},
	"computers": {
		Filter: fmt.Sprintf("(%s=computer)", analyze.AttrObjectClass),
		Attributes: []string{
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
			analyze.AttrName,
			analyze.AttrOperatingSystem,
			"operatingSystemVersion",
			analyze.AttrDNSHostName,
			analyze.AttrUserAccountControl,
			analyze.AttrObjectSID,
			analyze.AttrWhenCreated,
			analyze.AttrMSDSAllowedToDelegateTo,
			analyze.AttrMSDSAllowedToActOnBehalfOfOtherIdentity,
		},
	},
	"dc": {
		Filter: fmt.Sprintf("(&(%s=computer)(%s:%s:=%d))",
			analyze.AttrObjectClass,
			analyze.AttrUserAccountControl,
			analyze.OIDMatchRuleBitOr,
			analyze.UF_DOMAIN_CONTROLLER,
		),
		Attributes: []string{
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
			analyze.AttrName,
			analyze.AttrOperatingSystem,
			"operatingSystemVersion",
			analyze.AttrDNSHostName,
			analyze.AttrUserAccountControl,
			analyze.AttrObjectSID,
			analyze.AttrWhenCreated,
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
			"dn",
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
			analyze.AttrObjectClass,
			analyze.AttrSAMAccountName,
			analyze.AttrName,
			analyze.AttrMember,
			analyze.AttrMemberOf,
			analyze.AttrGroupType,
			analyze.AttrObjectSID,
			analyze.AttrWhenCreated,
			analyze.AttrAdminCount,
		},
	},
	"disabled": {
		Filter: fmt.Sprintf("(%s:%s:=%d)",
			analyze.AttrUserAccountControl,
			analyze.OIDMatchRuleBitOr,
			analyze.UF_ACCOUNTDISABLE,
		),
		Attributes: []string{
			"dn",
			analyze.AttrSAMAccountName,
			analyze.AttrUserPrincipalName,
			analyze.AttrLastLogonTimestamp,
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
	"machineAccountQuota": {
		Filter:     "(objectClass=domain)",
		Attributes: []string{"ms-DS-MachineAccountQuota"},
	},
}
