package analyze

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	aceTypeAccessAllowed       = 0x00
	aceTypeAccessDenied        = 0x01
	aceTypeAccessAllowedObject = 0x05
	aceTypeAccessDeniedObject  = 0x06
)

const (
	accessMaskGenericAll      = 0x10000000
	accessMaskGenericWrite    = 0x40000000
	accessMaskWriteDACL       = 0x00040000
	accessMaskWriteOwner      = 0x00080000
	accessMaskDelete          = 0x00010000
	accessMaskDSControlAccess = 0x00000100
	accessMaskDSSelf          = 0x00000008
	accessMaskDSWriteProp     = 0x00000020
)

const (
	sddlRevision1 = 1

	ownerSecurityInformation = 0x00000001
	groupSecurityInformation = 0x00000002
	daclSecurityInformation  = 0x00000004
	saclSecurityInformation  = 0x00000008
)

type aceSummary struct {
	Allow   bool
	Trustee string
	Mask    uint32
	Rights  []string
}

type sdSummary struct {
	OwnerSID string
	GroupSID string
	AceCount int
	HighRisk []aceSummary
}

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

func formatTrustee(sid string) string {
	if sid == "" {
		return ""
	}
	if name := wellKnownSIDName(sid); name != "" {
		return name + " (" + sid + ")"
	}
	return sid
}

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

func isHighRiskMask(mask uint32) bool {
	return mask&(accessMaskGenericAll|accessMaskGenericWrite|accessMaskWriteDACL|accessMaskWriteOwner|accessMaskDelete|accessMaskDSControlAccess|accessMaskDSWriteProp|accessMaskDSSelf) != 0
}

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

type parsedACL struct {
	AceCount int
	Aces     []aceSummary
}

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
	for i := 0; i < aceCount; i++ {
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

// securityDescriptorToSDDL converts binary security descriptor to SDDL string using Windows API
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
