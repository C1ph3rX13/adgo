package analyze

// LDAP Attributes
const (
	AttrObjectClass                             = "objectClass"
	AttrObjectGUID                              = "objectGUID"
	AttrObjectSID                               = "objectSid"
	AttrMSDSCreatorSID                          = "mS-DS-CreatorSID"
	AttrWhenCreated                             = "whenCreated"
	AttrWhenChanged                             = "whenChanged"
	AttrDSCorePropagationData                   = "dSCorePropagationData"
	AttrMSDSSupportedEncryptionTypes            = "msDS-SupportedEncryptionTypes"
	AttrLastLogon                               = "lastLogon"
	AttrPwdLastSet                              = "pwdLastSet"
	AttrLastLogonTimestamp                      = "lastLogonTimestamp"
	AttrBadPasswordTime                         = "badPasswordTime"
	AttrMSDSGenerationId                        = "msDS-GenerationId"
	AttrLogonHours                              = "logonHours"
	AttrMSDSAllowedToActOnBehalfOfOtherIdentity = "msDS-AllowedToActOnBehalfOfOtherIdentity"
	AttrNTSecurityDescriptor                    = "nTSecurityDescriptor"
	AttrUserAccountControl                      = "userAccountControl"
	AttrAccountExpires                          = "accountExpires"
	AttrSAMAccountName                          = "sAMAccountName"
	AttrUserPrincipalName                       = "userPrincipalName"
	AttrMSDSAllowedToDelegateTo                 = "msDS-AllowedToDelegateTo"
	AttrName                                    = "name"
	AttrOperatingSystem                         = "operatingSystem"
	AttrDNSHostName                             = "dNSHostName"
	AttrDistinguishedName                       = "distinguishedName"
	AttrCN                                      = "cn"
	AttrServicePrincipalName                    = "servicePrincipalName"
	AttrMember                                  = "member"
	AttrMemberOf                                = "memberOf"
	AttrGroupType                               = "groupType"
	AttrTrustDirection                          = "trustDirection"
	AttrTrustType                               = "trustType"
	AttrTrustAttributes                         = "trustAttributes"
	AttrFlatName                                = "flatName"
	AttrSIDHistory                              = "sIDHistory"
	AttrDisplayName                             = "displayName"
	AttrVersionNumber                           = "versionNumber"
	AttrGPCFileSysPath                          = "gPCFileSysPath"
	AttrGPCMachineExtensionNames                = "gPCMachineExtensionNames"
	AttrGPCUserExtensionNames                   = "gPCUserExtensionNames"
	AttrAdminCount                              = "adminCount"
	AttrObjectCategory                          = "objectCategory"
	AttrManagedBy                               = "managedBy"
)

// Configuration Keys
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

// Defaults
const (
	DefaultLDAPPort     = 389
	DefaultLDAPSecurity = 0
	DefaultOutputFormat = OutputFormatText
	DefaultLoginName    = "userPrincipalName"
	DefaultPagingSize   = 1000
)

// LDAP Matching Rules (OIDs)
const (
	OIDMatchRuleBitOr    = "1.2.840.113556.1.4.803"
	OIDMatchRuleBitAnd   = "1.2.840.113556.1.4.804"
	OIDMatchRuleInChain  = "1.2.840.113556.1.4.1941"
	OIDControlTypePaging = "1.2.840.113556.1.4.319"
)

// UserAccountControl Flags
const (
	UACAccountDisable               = 2
	UACEncryptedTextPasswordAllowed = 128
	UACNormalAccount                = 512
	UACInterdomainTrustAccount      = 2048
	UACWorkstationTrustAccount      = 4096
	UACServerTrustAccount           = 8192
	UACDontExpirePassword           = 65536
	UACMnsLogonAccount              = 131072
	UACSmartCardRequired            = 262144
	UACTrustedForDelegation         = 524288
	UACNotDelegated                 = 1048576
	UACUseDESKeyOnly                = 2097152
	UACDontRequirePreauth           = 4194304
	UACPasswordExpired              = 8388608
	UACTrustedToAuthForDelegation   = 16777216
	UACPartialSecretsAccount        = 67108864
)

// Common UAC Combinations
const (
	UACWorkstationOrServer = UACWorkstationTrustAccount | UACServerTrustAccount // 4096 | 8192 = 12288
	UACDomainController    = UACServerTrustAccount | UACTrustedForDelegation    // 8192 | 524288 = 532480
)
