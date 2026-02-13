package analyze

// LDAP Attribute Constants
// These constants map to Active Directory LDAP attribute names as defined in Microsoft specifications.
// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/04f6dde4-ce00-4fc5-82f0-f36d19518289

const (
	// Core Object Attributes
	AttrObjectClass                             = "objectClass"
	AttrObjectGUID                              = "objectGUID"
	AttrObjectSID                               = "objectSid"
	AttrDistinguishedName                       = "distinguishedName"
	AttrCN                                      = "cn"
	AttrName                                    = "name"
	AttrObjectCategory                          = "objectCategory"

	// Account Attributes
	AttrSAMAccountName                          = "sAMAccountName"
	AttrUserPrincipalName                       = "userPrincipalName"
	AttrUserAccountControl                      = "userAccountControl"
	AttrAccountExpires                          = "accountExpires"
	AttrPwdLastSet                              = "pwdLastSet"
	AttrAdminCount                              = "adminCount"

	// Security and Identity Attributes
	AttrMSDSCreatorSID                          = "mS-DS-CreatorSID"
	AttrSIDHistory                              = "sIDHistory"
	AttrNTSecurityDescriptor                    = "nTSecurityDescriptor"

	// Time Attributes
	AttrWhenCreated                             = "whenCreated"
	AttrWhenChanged                             = "whenChanged"
	AttrLastLogon                               = "lastLogon"
	AttrLastLogonTimestamp                      = "lastLogonTimestamp"
	AttrBadPasswordTime                         = "badPasswordTime"
	AttrDSCorePropagationData                   = "dSCorePropagationData"

	// Delegation and Authentication Attributes
	AttrMSDSAllowedToActOnBehalfOfOtherIdentity = "msDS-AllowedToActOnBehalfOfOtherIdentity"
	AttrMSDSAllowedToDelegateTo                 = "msDS-AllowedToDelegateTo"
	AttrMSDSSupportedEncryptionTypes            = "msDS-SupportedEncryptionTypes"
	AttrServicePrincipalName                    = "servicePrincipalName"
	AttrLogonHours                              = "logonHours"
	AttrMSDSGenerationId                        = "msDS-GenerationId"

	// Computer Attributes
	AttrOperatingSystem                         = "operatingSystem"
	AttrDNSHostName                             = "dNSHostName"

	// Group Attributes
	AttrMember                                  = "member"
	AttrMemberOf                                = "memberOf"
	AttrGroupType                               = "groupType"
	AttrManagedBy                               = "managedBy"

	// Trust Attributes
	AttrTrustDirection                          = "trustDirection"
	AttrTrustType                               = "trustType"
	AttrTrustAttributes                         = "trustAttributes"
	AttrFlatName                                = "flatName"

	// Display Attributes
	AttrDisplayName                             = "displayName"

	// GPO Attributes
	AttrGPCFileSysPath                          = "gPCFileSysPath"
	AttrGPCMachineExtensionNames                = "gPCMachineExtensionNames"
	AttrGPCUserExtensionNames                   = "gPCUserExtensionNames"
	AttrVersionNumber                           = "versionNumber"
)
