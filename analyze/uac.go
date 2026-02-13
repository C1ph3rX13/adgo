package analyze

import (
	"fmt"
	"strconv"
)

// UserAccountControl Attribute Flags
// https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
const (
	UF_ACCOUNTDISABLE                  = 0x0002    // The user account is disabled
	UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080    // The user password is stored under reversible encryption
	UF_NORMAL_ACCOUNT                  = 0x0200    // The account is a typical user account
	UF_INTERDOMAIN_TRUST_ACCOUNT       = 0x0800    // This is an account for a trusted domain that permits authentication to this domain
	UF_WORKSTATION_TRUST_ACCOUNT       = 0x1000    // This is a computer account for a Windows workstation or Windows server
	UF_SERVER_TRUST_ACCOUNT            = 0x2000    // This is a computer account for a domain controller that is a member of this domain
	UF_DONT_EXPIRE_PASSWORD            = 0x10000   // The password for this account will not expire
	UF_MNS_LOGON_ACCOUNT               = 0x20000   // This is an MNS logon account
	UF_SMARTCARD_REQUIRED              = 0x40000   // The user must log on using a smart card
	UF_TRUSTED_FOR_DELEGATION          = 0x80000   // The account is enabled for delegation
	UF_NOT_DELEGATED                   = 0x100000  // The security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation
	UF_USE_DES_KEY_ONLY                = 0x200000  // Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys
	UF_DONT_REQUIRE_PREAUTH            = 0x400000  // This account does not require Kerberos pre-authentication for logon
	UF_PASSWORD_EXPIRED                = 0x800000  // The user password has expired
	UF_TRUSTED_TO_AUTH_FOR_DELEGATION  = 0x1000000 // The account is trusted to authenticate a user outside of the Kerberos security boundary and is authorized for delegation
	UF_PARTIAL_SECRETS_ACCOUNT         = 0x4000000 // Partial secrets account
)

// Common UAC combinations
const (
	UF_WORKSTATION_OR_SERVER = UF_WORKSTATION_TRUST_ACCOUNT | UF_SERVER_TRUST_ACCOUNT // 0x3000
	UF_DOMAIN_CONTROLLER     = UF_SERVER_TRUST_ACCOUNT | UF_TRUSTED_FOR_DELEGATION    // 0x82000
)

// ParseUserAccountControl parses UserAccountControl value to string representation.
// The function uses Microsoft standard UAC flags (UF_* constants) to identify account types.
//
// Parameters:
//   - uacStr: UserAccountControl value as string (decimal representation)
//
// Returns:
//   - Formatted string with UAC decimal value and account type description
//   - An error if the input cannot be parsed as uint32
func ParseUserAccountControl(uacStr string) (string, error) {
	// Parse string to unsigned integer
	uac, err := strconv.ParseUint(uacStr, 10, 32)
	if err != nil {
		return "", fmt.Errorf("failed to parse userAccountControl: %w", err)
	}

	// Identify account type using Microsoft UF_* constants
	switch uac {
	case UF_DOMAIN_CONTROLLER:
		return fmt.Sprintf("%d, Domain Controller", uac), nil
	case UF_WORKSTATION_OR_SERVER:
		return fmt.Sprintf("%d, Workstation / Server", uac), nil
	case UF_INTERDOMAIN_TRUST_ACCOUNT | UF_PASSWORD_EXPIRED:
		// krbtgt account with expired password pattern
		return fmt.Sprintf("%d, Krbtgt (Expired)", uac), nil
	case UF_INTERDOMAIN_TRUST_ACCOUNT:
		// krbtgt account pattern (typically UF_INTERDOMAIN_TRUST_ACCOUNT for krbtgt)
		return fmt.Sprintf("%d, Krbtgt", uac), nil
	case UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE:
		// Typical disabled user account (common pattern for guest users)
		return fmt.Sprintf("%d, Disabled User", uac), nil
	case UF_NORMAL_ACCOUNT:
		return fmt.Sprintf("%d, User", uac), nil
	default:
		return fmt.Sprintf("%d, Unknown", uac), nil
	}
}
