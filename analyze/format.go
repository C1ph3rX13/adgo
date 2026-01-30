package analyze

import (
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// FormatAttributeValue retrieves and formats attribute values based on the attribute name
func FormatAttributeValue(entry *ldap.Entry, attribute string) (string, error) {
	switch attribute {
	case AttrObjectClass:
		return FormatObjectClass(entry, attribute)

	case AttrObjectGUID:
		binaryGUID := entry.GetRawAttributeValue(attribute)
		return ParseObjectGUID(binaryGUID)

	case AttrObjectSID, AttrMSDSCreatorSID:
		binarySID := entry.GetRawAttributeValue(attribute)
		return ParseObjectSID(binarySID)

	case AttrWhenCreated, AttrWhenChanged, AttrDSCorePropagationData:
		return GeneralizedTime(entry, attribute)

	case AttrMSDSSupportedEncryptionTypes:
		return MSDSSupportedEncryptionTypes(entry, attribute)

	case AttrLastLogon, AttrPwdLastSet, AttrLastLogonTimestamp, AttrBadPasswordTime:
		return FileTimeToTime(entry, attribute)

	case AttrMSDSGenerationId, AttrLogonHours, AttrMSDSAllowedToActOnBehalfOfOtherIdentity:
		return AttributeHex(entry, attribute)

	case AttrNTSecurityDescriptor:
		raw := entry.GetRawAttributeValue(attribute)
		if len(raw) == 0 {
			return "", nil
		}
		// Try summary format first
		if summary, err := formatSDSummary(raw); err == nil && summary != "" {
			return summary, nil
		}
		// Try SDDL format (Windows only usually)
		if sddl, err := securityDescriptorToSDDL(raw); err == nil && sddl != "" {
			return sddl, nil
		}
		// Fallback to hex
		return attributeHexBytes(raw), nil

	case AttrUserAccountControl:
		uacStr := entry.GetAttributeValue(attribute)
		return ParseUserAccountControl(uacStr)

	case AttrAccountExpires:
		return AccountExpires(entry, attribute)

	default:
		v := entry.GetAttributeValue(attribute)
		if v == "" {
			return "", nil
		}
		// Check if value looks like binary
		if isBinaryLikeString(v) {
			raw := entry.GetRawAttributeValue(attribute)
			if len(raw) > 0 {
				return attributeHexBytes(raw), nil
			}
		}
		return v, nil
	}
}

// FormatObjectClass retrieves and joins objectClass values
// Note: LDAP objectClass is multi-valued, usually the last one is the most specific class.
func FormatObjectClass(entry *ldap.Entry, attribute string) (string, error) {
	classes := entry.GetAttributeValues(attribute)

	if len(classes) == 0 {
		return "", errors.New("invalid objectClass: no values found")
	}

	return strings.Join(classes, ","), nil
}
