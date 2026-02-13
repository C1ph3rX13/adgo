package queries

import (
	"adgo/analyze"
	"fmt"
)

// privilegeQueries contains privilege and group membership queries
var privilegeQueries = map[string]Query{
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
