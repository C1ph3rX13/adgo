package analyze

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ACE (Access Control Entry) type constants
// These constants define the types of Access Control Entries in Windows security descriptors.
// Reference: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
//
// These are unexported as they are only used internally within this package.
// If external access is needed, consider exporting with AceType* prefix.
const (
	aceTypeAccessAllowed       = 0x00 // ACCESS_ALLOWED_ACE_TYPE - Allows access to specified rights
	aceTypeAccessDenied        = 0x01 // ACCESS_DENIED_ACE_TYPE - Denies access to specified rights
	aceTypeAccessAllowedObject = 0x05 // ACCESS_ALLOWED_OBJECT_ACE_TYPE - Allows access with object-specific GUIDs
	aceTypeAccessDeniedObject  = 0x06 // ACCESS_DENIED_OBJECT_ACE_TYPE - Denies access with object-specific GUIDs
)

// Access mask constants for ACL rights
// These constants define the specific access rights that can be granted or denied in an ACE.
// Reference: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_mask
//
// These are unexported as they are only used internally within this package.
// If external access is needed, consider exporting with AccessMask* prefix.
const (
	accessMaskGenericAll      = 0x10000000 // GENERIC_ALL - All possible access rights
	accessMaskGenericWrite    = 0x40000000 // GENERIC_WRITE - Write access to the entire object
	accessMaskWriteDACL       = 0x00040000 // WRITE_DAC - Right to modify the DACL (Discretionary Access Control List)
	accessMaskWriteOwner      = 0x00080000 // WRITE_OWNER - Right to take ownership of the object
	accessMaskDelete          = 0x00010000 // DELETE - Right to delete the object
	accessMaskDSControlAccess = 0x00000100 // ADS_RIGHT_DS_CONTROL_ACCESS - Right to perform extended access control
	accessMaskDSSelf          = 0x00000008 // ADS_RIGHT_DS_SELF - Right to perform a validated write to a property
	accessMaskDSWriteProp     = 0x00000020 // ADS_RIGHT_DS_WRITE_PROP - Right to write properties of the object
)

// Security Descriptor Definition Language (SDDL) constants
// These constants are used for converting security descriptors to SDDL string format.
// Reference: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-convertsecuritydescriptortostringsecuritydescriptorw
//
// These are unexported as they are only used internally within this package.
const (
	sddlRevision1 = 1 // SDDL revision 1 - The current revision level of SDDL

	// Security information flags for SDDL string generation
	// These flags specify which parts of the security descriptor to include in the SDDL string
	ownerSecurityInformation = 0x00000001 // OWNER_SECURITY_INFORMATION - Include the owner SID
	groupSecurityInformation = 0x00000002 // GROUP_SECURITY_INFORMATION - Include the primary group SID
	daclSecurityInformation  = 0x00000004 // DACL_SECURITY_INFORMATION - Include the discretionary ACL
	saclSecurityInformation  = 0x00000008 // SACL_SECURITY_INFORMATION - Include the system ACL
)

// aceSummary represents a simplified summary of an Access Control Entry (ACE).
// It captures the key information needed for security analysis: whether the ACE allows or denies access,
// the trustee (account/group) affected, the access mask, and the specific rights granted/denied.
type aceSummary struct {
	Allow   bool     // true if this is an allowed ACE, false if denied
	Trustee string   // SID of the account/group this ACE applies to
	Mask    uint32   // Access mask containing the rights
	Rights  []string // Human-readable names for the rights in this ACE
}

// sdSummary represents a simplified summary of a Security Descriptor.
// It contains ownership information, ACL statistics, and high-risk ACEs that may indicate security issues.
type sdSummary struct {
	OwnerSID string       // SID of the object owner
	GroupSID string       // SID of the primary group
	AceCount int          // Total number of ACEs in the DACL
	HighRisk []aceSummary // List of high-risk ACEs (those with dangerous rights)
}

// wellKnownSIDName returns the friendly name for well-known Windows SIDs.
// It converts well-known security identifier strings to their human-readable names.
//
// Parameters:
//   - sid: The SID string to look up (e.g., "S-1-5-32-544")
//
// Returns:
//   - The friendly name if the SID is well-known (e.g., "Administrators" for "S-1-5-32-544")
//   - Empty string if the SID is not in the well-known list
//
// Supported well-known SIDs:
//   - S-1-1-0: Everyone
//   - S-1-5-11: Authenticated Users
//   - S-1-5-32-544: Administrators
//   - S-1-5-32-545: Users
//   - S-1-5-32-548: Account Operators
//   - S-1-5-32-549: Server Operators
//   - S-1-5-32-550: Print Operators
//   - S-1-5-32-551: Backup Operators
//
// Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
func wellKnownSIDName(sid string) string {
	switch sid {
	case "S-1-1-0":
		return "Everyone"
	case "S-1-5-11":
		return "Authenticated Users"
	case "S-1-5-32-544":
		return "Administrators"
	case "S-1-5-32-545":
		return "Users"
	case "S-1-5-32-548":
		return "Account Operators"
	case "S-1-5-32-549":
		return "Server Operators"
	case "S-1-5-32-550":
		return "Print Operators"
	case "S-1-5-32-551":
		return "Backup Operators"
	default:
		return ""
	}
}

// formatTrustee formats a SID string for display, optionally including the well-known name.
// If the SID corresponds to a well-known account, it returns "Name (SID)", otherwise returns the SID as-is.
//
// Parameters:
//   - sid: The SID string to format
//
// Returns:
//   - Formatted trustee string with well-known name if applicable
func formatTrustee(sid string) string {
	if sid == "" {
		return ""
	}
	if name := wellKnownSIDName(sid); name != "" {
		return name + " (" + sid + ")"
	}
	return sid
}

// decodeRiskyRights decodes an access mask into human-readable right names.
// It extracts risky access rights that could indicate security concerns if granted inappropriately.
//
// Parameters:
//   - mask: The access mask to decode
//
// Returns:
//   - A slice of human-readable right names present in the mask
func decodeRiskyRights(mask uint32) []string {
	var rights []string
	if mask&accessMaskGenericAll != 0 {
		rights = append(rights, "GENERIC_ALL")
	}
	if mask&accessMaskGenericWrite != 0 {
		rights = append(rights, "GENERIC_WRITE")
	}
	if mask&accessMaskWriteDACL != 0 {
		rights = append(rights, "WRITE_DACL")
	}
	if mask&accessMaskWriteOwner != 0 {
		rights = append(rights, "WRITE_OWNER")
	}
	if mask&accessMaskDelete != 0 {
		rights = append(rights, "DELETE")
	}
	if mask&accessMaskDSControlAccess != 0 {
		rights = append(rights, "CONTROL_ACCESS")
	}
	if mask&accessMaskDSWriteProp != 0 {
		rights = append(rights, "WRITE_PROP")
	}
	if mask&accessMaskDSSelf != 0 {
		rights = append(rights, "SELF")
	}
	return rights
}

// isHighRiskMask checks if an access mask contains any high-risk rights.
// High-risk rights are those that could lead to privilege escalation or security issues if granted inappropriately.
//
// Parameters:
//   - mask: The access mask to check
//
// Returns:
//   - true if the mask contains any high-risk rights, false otherwise
func isHighRiskMask(mask uint32) bool {
	return mask&(accessMaskGenericAll|accessMaskGenericWrite|accessMaskWriteDACL|accessMaskWriteOwner|accessMaskDelete|accessMaskDSControlAccess|accessMaskDSWriteProp|accessMaskDSSelf) != 0
}

// parseSecurityDescriptorRelative parses a self-relative security descriptor and extracts key information.
// It decodes the binary security descriptor format and returns ownership information and high-risk ACEs.
//
// Parameters:
//   - raw: The raw bytes of the security descriptor in self-relative format
//
// Returns:
//   - A sdSummary containing owner, group, ACE count, and high-risk ACEs
//   - An error if the security descriptor is invalid or too short
func parseSecurityDescriptorRelative(raw []byte) (sdSummary, error) {
	var out sdSummary
	if len(raw) < 20 {
		return out, fmt.Errorf("security descriptor too short")
	}

	ownerOff := binary.LittleEndian.Uint32(raw[4:8])
	groupOff := binary.LittleEndian.Uint32(raw[8:12])
	daclOff := binary.LittleEndian.Uint32(raw[16:20])

	if ownerOff != 0 && int(ownerOff) < len(raw) {
		if sid, err := ParseObjectSID(raw[ownerOff:]); err == nil {
			out.OwnerSID = sid
		}
	}
	if groupOff != 0 && int(groupOff) < len(raw) {
		if sid, err := ParseObjectSID(raw[groupOff:]); err == nil {
			out.GroupSID = sid
		}
	}

	if daclOff == 0 || int(daclOff) >= len(raw) {
		return out, nil
	}
	acl, err := parseACL(raw[daclOff:])
	if err != nil {
		return out, err
	}
	out.AceCount = acl.AceCount
	for _, a := range acl.Aces {
		if isHighRiskMask(a.Mask) {
			out.HighRisk = append(out.HighRisk, a)
		}
	}
	return out, nil
}

// parsedACL represents the result of parsing a binary ACL structure.
// It contains the total ACE count and a list of all ACE summaries extracted from the ACL.
type parsedACL struct {
	AceCount int          // Number of ACEs in the ACL
	Aces     []aceSummary // List of parsed ACE summaries
}

// parseACL parses a binary ACL structure and extracts all ACEs.
// It decodes the ACL header and iterates through all ACEs, extracting trustee and rights information.
//
// Parameters:
//   - b: The raw bytes of the ACL structure
//
// Returns:
//   - A parsedACL containing the ACE count and all parsed ACE summaries
//   - An error if the ACL is invalid or too short
func parseACL(b []byte) (parsedACL, error) {
	var out parsedACL
	if len(b) < 8 {
		return out, fmt.Errorf("acl too short")
	}
	aclSize := int(binary.LittleEndian.Uint16(b[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(b[4:6]))
	if aclSize < 8 || aclSize > len(b) {
		return out, fmt.Errorf("invalid acl size")
	}
	out.AceCount = aceCount

	off := 8
	for range aceCount {
		if off+4 > aclSize {
			break
		}
		aceType := b[off]
		aceSize := int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
		if aceSize < 4 || off+aceSize > aclSize {
			break
		}
		aceBytes := b[off : off+aceSize]

		if aceType == aceTypeAccessAllowed || aceType == aceTypeAccessDenied {
			if aceSize < 8 {
				off += aceSize
				continue
			}
			mask := binary.LittleEndian.Uint32(aceBytes[4:8])
			sidBytes := aceBytes[8:]
			trustee, _ := ParseObjectSID(sidBytes)
			out.Aces = append(out.Aces, aceSummary{
				Allow:   aceType == aceTypeAccessAllowed,
				Trustee: trustee,
				Mask:    mask,
				Rights:  decodeRiskyRights(mask),
			})
		} else if aceType == aceTypeAccessAllowedObject || aceType == aceTypeAccessDeniedObject {
			if aceSize < 16 {
				off += aceSize
				continue
			}
			mask := binary.LittleEndian.Uint32(aceBytes[4:8])
			flags := binary.LittleEndian.Uint32(aceBytes[8:12])
			cursor := 12
			if flags&0x1 != 0 {
				cursor += 16
			}
			if flags&0x2 != 0 {
				cursor += 16
			}
			if cursor >= aceSize {
				off += aceSize
				continue
			}
			trustee, _ := ParseObjectSID(aceBytes[cursor:])
			out.Aces = append(out.Aces, aceSummary{
				Allow:   aceType == aceTypeAccessAllowedObject,
				Trustee: trustee,
				Mask:    mask,
				Rights:  decodeRiskyRights(mask),
			})
		}
		off += aceSize
	}
	return out, nil
}

// formatSDSummary formats a security descriptor as a human-readable summary string.
// It provides ownership, group, DACL statistics, and up to 3 high-risk ACEs.
//
// Parameters:
//   - raw: The raw bytes of the security descriptor
//
// Returns:
//   - A formatted summary string containing owner, group, DACL count, high-risk count, and top high-risk ACEs
//   - An error if the security descriptor cannot be parsed
func formatSDSummary(raw []byte) (string, error) {
	s, err := parseSecurityDescriptorRelative(raw)
	if err != nil {
		return "", err
	}

	owner := s.OwnerSID
	group := s.GroupSID
	if owner != "" {
		owner = formatTrustee(owner)
	}
	if group != "" {
		group = formatTrustee(group)
	}

	high := len(s.HighRisk)
	var top []string
	for i, a := range s.HighRisk {
		if i >= 3 {
			break
		}
		kind := "ALLOW"
		if !a.Allow {
			kind = "DENY"
		}
		rights := strings.Join(a.Rights, "|")
		if rights == "" {
			rights = fmt.Sprintf("0x%08X", a.Mask)
		}
		top = append(top, kind+" "+formatTrustee(a.Trustee)+" "+rights)
	}

	out := fmt.Sprintf("Owner=%s; Group=%s; DACL=%d ACE; HighRisk=%d", owner, group, s.AceCount, high)
	if len(top) > 0 {
		out += "; Top=" + strings.Join(top, " | ")
	}
	return out, nil
}

// securityDescriptorToSDDL converts a binary security descriptor to SDDL string format using the Windows API.
// Security Descriptor Definition Language (SDDL) is a string format for representing security descriptors.
//
// Parameters:
//   - raw: The raw bytes of the security descriptor
//
// Returns:
//   - The SDDL string representation of the security descriptor
//   - An error if the conversion fails
//
// Note: This function requires Windows and uses the ConvertSecurityDescriptorToStringSecurityDescriptorW API.
// Reference: https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw
func securityDescriptorToSDDL(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}

	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	proc := advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")

	var sddlPtr *uint16
	var sddlLen uint32

	secInfo := uint32(ownerSecurityInformation | groupSecurityInformation | daclSecurityInformation)

	r1, _, err := proc.Call(
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(sddlRevision1),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&sddlPtr)),
		uintptr(unsafe.Pointer(&sddlLen)),
	)
	if r1 == 0 {
		if err != nil && err != windows.ERROR_SUCCESS {
			return "", fmt.Errorf("ConvertSecurityDescriptorToStringSecurityDescriptorW: %w", err)
		}
		return "", fmt.Errorf("ConvertSecurityDescriptorToStringSecurityDescriptorW failed")
	}
	if sddlPtr == nil {
		return "", fmt.Errorf("ConvertSecurityDescriptorToStringSecurityDescriptorW returned nil")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(sddlPtr)))

	return windows.UTF16PtrToString(sddlPtr), nil
}
