package analyze

import (
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// FormatAttributeValue retrieves and formats an LDAP attribute value based on the attribute name.
// It delegates to specialized formatters for known attribute types to provide human-readable output.
//
// Parameters:
//   - entry: The LDAP entry containing the attribute to format
//   - attribute: The name of the attribute to format (should match constants in attributes.go)
//
// Returns:
//   - The formatted string representation of the attribute value
//   - An error if the attribute cannot be formatted or is invalid
//
// Supported specialized formatters:
//   - ObjectClass: Multi-valued attribute, joined with commas
//   - ObjectGUID: Binary GUID converted to string format
//   - ObjectSID/mS-DS-CreatorSID: Binary SID converted to string format
//   - Time attributes (whenCreated, whenChanged, etc.): GeneralizedTime conversion
//   - FileTime attributes (lastLogon, pwdLastSet, etc.): Windows FileTime conversion
//   - msDS-SupportedEncryptionTypes: Encryption types list
//   - nTSecurityDescriptor: SDDL or summary format
//   - userAccountControl: UAC flag parsing
//   - accountExpires: Account expiration handling
//
// For unknown attributes, returns the raw string value or hex representation if binary-like.
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

// FormatObjectClass retrieves and joins objectClass values.
// The objectClass attribute is multi-valued; this function joins all values with commas.
// Typically, the last value in the list is the most specific object class.
//
// Parameters:
//   - entry: The LDAP entry containing the objectClass attribute
//   - attribute: The attribute name (typically "objectClass")
//
// Returns:
//   - A comma-separated string of all objectClass values
//   - An error if no objectClass values are found
func FormatObjectClass(entry *ldap.Entry, attribute string) (string, error) {
	classes := entry.GetAttributeValues(attribute)

	if len(classes) == 0 {
		return "", errors.New("invalid objectClass: no values found")
	}

	return strings.Join(classes, ","), nil
}
