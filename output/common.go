package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/go-ldap/ldap/v3"
)

// colorFunctions holds color functions for output formatting
type colorFunctions struct {
	Red    func(...interface{}) string
	Green  func(...interface{}) string
	Yellow func(...interface{}) string
	Blue   func(...interface{}) string
	Cyan   func(...interface{}) string
	Bold   func(...interface{}) string
	Dim    func(...interface{}) string
}

// initColors initializes color functions based on terminal support
func initColors() colorFunctions {
	if color.NoColor {
		return colorFunctions{
			Red:    fmt.Sprint,
			Green:  fmt.Sprint,
			Yellow: fmt.Sprint,
			Blue:   fmt.Sprint,
			Cyan:   fmt.Sprint,
			Bold:   fmt.Sprint,
			Dim:    fmt.Sprint,
		}
	}

	return colorFunctions{
		Red:    color.New(color.FgRed).SprintFunc(),
		Green:  color.New(color.FgGreen).SprintFunc(),
		Yellow: color.New(color.FgYellow).SprintFunc(),
		Blue:   color.New(color.FgBlue).SprintFunc(),
		Cyan:   color.New(color.FgCyan).SprintFunc(),
		Bold:   color.New(color.Bold).SprintFunc(),
		Dim:    color.New(color.Faint).SprintFunc(),
	}
}

// objectType determines the AD object type from its distinguished name
func objectType(dn string) string {
	switch {
	case strings.Contains(dn, "OU=Domain Controllers,"):
		return "DC"
	case strings.Contains(dn, "CN=Computers,"):
		return "COMPUTER"
	case strings.Contains(dn, "CN=Users,") || strings.Contains(dn, "OU=Users,"):
		return "USER"
	case strings.Contains(dn, "CN=Groups,") || strings.Contains(dn, "OU=Groups,"):
		return "GROUP"
	case strings.Contains(dn, "OU="):
		return "OU"
	default:
		return "OTHER"
	}
}

// collectStats collects statistics from a list of LDAP entries
func collectStats(entries []*ldap.Entry) Statistics {
	stats := Statistics{}
	for _, e := range entries {
		stats.Total++
		objType := objectType(e.DN)
		attrs := formatEntryAttributes(e)

		switch objType {
		case "USER":
			uac := attrs["userAccountControl"]
			// Check both "ACCOUNTDISABLE" and "Disabled User" to handle all cases
			// "Disabled User" is returned by analyze.ParseUserAccountControl for UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE
			if strings.Contains(uac, "ACCOUNTDISABLE") || strings.Contains(uac, "Disabled User") {
				stats.Disabled++
			} else {
				stats.Enabled++
			}

			if attrs["adminCount"] == "1" {
				stats.Admins++
			}

			if attrs["servicePrincipalName"] != "" {
				stats.SPN++
			}

			// AS-REP Roastable: doesn't have PREAUTH_NOT_REQUIRED and is not disabled
			if !strings.Contains(uac, "PREAUTH_NOT_REQUIRED") &&
				!strings.Contains(uac, "DONT_REQUIRE_PREAUTH") &&
				!strings.Contains(uac, "ACCOUNTDISABLE") &&
				!strings.Contains(uac, "Disabled User") {
				stats.ASRep++
			}

		case "DC":
			// Domain Controllers are counted separately
			stats.DCs++
			// DCs are also counted as enabled computers
			stats.Enabled++

		case "COMPUTER":
			// Regular computers - count as enabled unless disabled
			if !strings.Contains(attrs["userAccountControl"], "ACCOUNTDISABLE") {
				stats.Enabled++
			}
		}
	}
	return stats
}

// isHighValueTarget checks if an entry represents a high-value target
func isHighValueTarget(entry *ldap.Entry) bool {
	attrs := formatEntryAttributes(entry)

	// Check adminCount
	if attrs["adminCount"] == "1" {
		return true
	}

	// Check for Domain Controllers
	if strings.Contains(entry.DN, "OU=Domain Controllers,") {
		return true
	}

	// Check for sensitive SPN accounts
	if spn := attrs["servicePrincipalName"]; spn != "" {
		// High-value SPN services
		sensitiveSPNs := []string{
			"MSSQLSvc", "HTTP", "cifs", "GC", "ldap", "krbtgt",
		}
		for _, s := range sensitiveSPNs {
			if strings.HasPrefix(spn, s) {
				return true
			}
		}
	}

	return false
}

// scoreTarget calculates a value score for an entry for sorting
func scoreTarget(entry *ldap.Entry) int {
	score := 0
	objType := objectType(entry.DN)
	attrs := formatEntryAttributes(entry)

	switch objType {
	case "USER":
		// Admin account: +50
		if attrs["adminCount"] == "1" {
			score += 50
		}

		// SPN account: +20
		if attrs["servicePrincipalName"] != "" {
			score += 20
		}

		// AS-REP Roastable (PREAUTH_NOT_REQUIRED not set): +15
		uac := attrs["userAccountControl"]
		if !strings.Contains(uac, "PREAUTH_NOT_REQUIRED") &&
			!strings.Contains(uac, "DONT_REQUIRE_PREAUTH") &&
			!strings.Contains(uac, "ACCOUNTDISABLE") &&
			!strings.Contains(uac, "Disabled User") {
			score += 15
		}

		// Recent logon: +10
		if attrs["lastLogon"] != "" && attrs["lastLogon"] != "Never" {
			score += 10
		}

		// Password not expired: +5
		if strings.Contains(uac, "DONT_EXPIRE_PASSWORD") {
			score += 5
		}

	case "COMPUTER", "DC":
		// Domain Controller: +40
		if strings.Contains(entry.DN, "OU=Domain Controllers,") {
			score += 40
		}

		// Recent logon: +10
		if attrs["lastLogon"] != "" && attrs["lastLogon"] != "Never" {
			score += 10
		}

	case "GROUP":
		// Admin group: +30
		if attrs["adminCount"] == "1" {
			score += 30
		}

		// Large group: +5
		if memberCount := attrs["memberCount"]; memberCount != "" {
			// Parse count if numeric
			var count int
			if _, err := fmt.Sscanf(memberCount, "%d", &count); err == nil && count > 10 {
				score += 5
			}
		}
	}

	return score
}

// sortByValue sorts entries by their value score (highest first)
func sortByValue(entries []*ldap.Entry) []*ldap.Entry {
	sorted := make([]*ldap.Entry, len(entries))
	copy(sorted, entries)

	sort.Slice(sorted, func(i, j int) bool {
		return scoreTarget(sorted[i]) > scoreTarget(sorted[j])
	})

	return sorted
}
