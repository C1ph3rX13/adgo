package analyze

import (
	"fmt"
	"strconv"
)

// ParseUserAccountControl parses UserAccountControl value to string representation
// uacStr: UserAccountControl value as string
// Returns: Formatted string with UAC value and account type
func ParseUserAccountControl(uacStr string) (string, error) {
	// Parse string to unsigned integer
	uac, err := strconv.ParseUint(uacStr, 10, 32)
	if err != nil {
		return "Unknown", fmt.Errorf("failed to parse userAccountControl: %v", err)
	}

	// Identify account type
	switch {
	case uac == 0x82000: // Domain Controller
		return fmt.Sprintf("%d, Domain Controller", uac), nil
	case uac == 0x1000: // Workstation / Server
		return fmt.Sprintf("%d, Workstation / Server", uac), nil
	case uac == 0x820: // Trust
		return fmt.Sprintf("%d, Trust", uac), nil
	case uac == 0x200: // Typical User
		return fmt.Sprintf("%d, User", uac), nil
	case uac == 0x10222: // Guest User
		return fmt.Sprintf("%d, Guest", uac), nil
	case uac == 0x202: // Krbtgt User
		return fmt.Sprintf("%d, Krbtgt", uac), nil
	default:
		return fmt.Sprintf("%d, Unknown", uac), nil
	}
}
