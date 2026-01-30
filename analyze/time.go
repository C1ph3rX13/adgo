package analyze

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	// FileTimeToUnixEpochDiff is the difference between Windows FileTime epoch (1601-01-01) and Unix epoch (1970-01-01) in 100-nanosecond intervals
	FileTimeToUnixEpochDiff = 1164447360000000000
	// NanoSecondsPerHundredNanoSeconds is the conversion factor from 100-nanosecond intervals to nanoseconds
	NanoSecondsPerHundredNanoSeconds = 100
)

// GeneralizedTime converts LDAP generalized time attribute to datetime string
func GeneralizedTime(entry *ldap.Entry, attribute string) (string, error) {
	generalizedTime := entry.GetAttributeValue(attribute)
	return GeneralizedTimeToDateTime(generalizedTime)
}

// GeneralizedTimeToDateTime converts LDAP generalized time to date-time format
// generalizedTime: LDAP generalized time string (e.g., "20230101120000.0Z")
// Returns: Formatted time string in "2006-01-02 15:04:05" format
func GeneralizedTimeToDateTime(generalizedTime string) (string, error) {
	if generalizedTime == "" {
		return "", fmt.Errorf("empty generalized time string")
	}

	t, err := time.Parse("20060102150405.0Z", generalizedTime)
	if err != nil {
		return "", err
	}

	return t.Local().Format(time.DateTime), nil
}

// FileTimeToTime converts Windows FileTime attribute to formatted datetime string
// Supported attributes: lastLogon, pwdLastSet, lastLogonTimestamp, badPasswordTime
// Returns: Formatted time string "2006-01-02 15:04:05" (UTC)
func FileTimeToTime(entry *ldap.Entry, attribute string) (string, error) {
	// Parameter validation
	if entry == nil {
		return "", fmt.Errorf("ldap entry is nil")
	}
	if attribute == "" {
		return "", fmt.Errorf("attribute name is empty")
	}

	// Get attribute value
	rawValue := entry.GetAttributeValue(attribute)
	if rawValue == "" {
		return "", fmt.Errorf("attribute '%s' not found or is empty", attribute)
	}

	return ParseFileTimeToTime(rawValue)
}

// ParseFileTimeToTime converts Windows FileTime to human-readable time format
// fileTimeStr: Windows FileTime as a string (18-digit number)
// Returns: Formatted time string in "2006-01-02 15:04:05" format
func ParseFileTimeToTime(fileTimeStr string) (string, error) {
	if fileTimeStr == "" {
		return "", fmt.Errorf("empty fileTime string")
	}

	// Convert to integer (Windows FileTime is 18-digit numeric string)
	fileTime, err := strconv.ParseInt(fileTimeStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse fileTime: %w", err)
	}

	// Handle special value: 0 means never occurred (e.g., never logged on)
	if fileTime == 0 {
		return "", fmt.Errorf("zero value for fileTime (never occurred)")
	}

	// Time conversion logic
	var unixNano int64
	if fileTime >= FileTimeToUnixEpochDiff {
		// Normal case: time value from 1601-01-01
		unixNano = (fileTime - FileTimeToUnixEpochDiff) * NanoSecondsPerHundredNanoSeconds
	} else {
		// Abnormal case: value less than epochDiff (e.g., future time or invalid data)
		return "", fmt.Errorf("invalid filetime value '%d'", fileTime)
	}

	// Construct time.Time object and format output
	timestamp := time.Unix(0, unixNano).UTC()
	return timestamp.Format(time.DateTime), nil
}

// AccountExpires parses accountExpires attribute value to readable date format
// Supports:
// - "0" and "9223372036854775807" meaning "never"
// - Normal FILETIME timestamps (100ns since 1601-01-01) converted to UTC
func AccountExpires(entry *ldap.Entry, attribute string) (string, error) {
	b := entry.GetAttributeValue(attribute)

	// 1. Remove empty values
	if b == "" {
		return "", nil
	}

	// 2. Try to parse string to Int64
	ft, err := strconv.ParseInt(b, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid accountExpires value: %w", err)
	}

	// 3. Check for "never" cases
	if ft == 0 || ft == 9223372036854775807 {
		return "9223372036854775807, never", nil
	}

	// 4. Convert FILETIME to Unix timestamp
	// FILETIME is 100ns intervals since 1601-01-01
	const fileTimeToUnixEpochNs = 116444736000000000    // 1601-01-01 00:00:00 UTC to 1970-01-01 in 100ns units
	unixTime := (ft - fileTimeToUnixEpochNs) / 10000000 // Convert to seconds

	// 5. Check if it's a valid Unix timestamp
	if unixTime < 0 {
		return "", fmt.Errorf("accountExpires value out of range: %d", ft)
	}

	// 6. Convert to UTC time and format as string
	t := time.Unix(unixTime, 0).UTC()

	// 7. Return original timestamp and formatted UTC time string
	ae := fmt.Sprintf("%v,%v", b, t.Format(time.DateTime))

	return ae, nil
}
