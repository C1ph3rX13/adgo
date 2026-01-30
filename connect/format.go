package connect

import (
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// UserPrincipal generates User Principal Name (UPN)
func UserPrincipal(baseDN string, username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username cannot be empty")
	}

	if strings.Contains(username, "@") {
		if _, err := mail.ParseAddress(username); err != nil {
			return "", fmt.Errorf("username %s looks like UPN but is invalid: %v", username, err)
		}
		return username, nil
	}

	domain, err := BaseDNToDomain(baseDN)
	if err != nil {
		return "", fmt.Errorf("failed to parse domain from BaseDN '%s': %v", baseDN, err)
	}

	return fmt.Sprintf("%s@%s", username, domain), nil
}

// BaseDNToDomain converts BaseDN to domain name
// baseDN: LDAP BaseDN string (e.g., "DC=sec,DC=lab")
// Returns: Domain name (e.g., "sec.lab") or error if invalid
func BaseDNToDomain(baseDN string) (string, error) {
	baseDN = strings.TrimSpace(baseDN)
	if baseDN == "" {
		return "", fmt.Errorf("empty baseDN")
	}

	parts := strings.Split(baseDN, ",")
	var domainParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		lowerPart := strings.ToLower(part)
		if strings.HasPrefix(lowerPart, "dc=") {
			dcValue := strings.TrimPrefix(lowerPart, "dc=")
			if dcValue != "" {
				domainParts = append(domainParts, dcValue)
			}
		}
	}

	if len(domainParts) == 0 {
		return "", fmt.Errorf("no DC components found in baseDN: %s", baseDN)
	}

	return strings.Join(domainParts, "."), nil
}

// GenerateFilename generates a CSV filename with domain and timestamp
func GenerateFilename(baseDN string) string {
	domain, err := BaseDNToDomain(baseDN)
	if err != nil {
		domain = "ad"
	}
	timestamp := time.Now().Format("20060102-150405")
	return fmt.Sprintf("%s-%s.csv", domain, timestamp)
}

// DomainAdminsDN returns the distinguished name for Domain Admins group
func DomainAdminsDN(baseDN string) string {
	return "CN=Domain Admins,CN=Users," + baseDN
}

// EnterpriseAdminsDN returns the distinguished name for Enterprise Admins group
func EnterpriseAdminsDN(baseDN string) string {
	return "CN=Enterprise Admins,CN=Users," + baseDN
}

// SchemaAdminsDN returns the distinguished name for Schema Admins group
func SchemaAdminsDN(baseDN string) string {
	return "CN=Schema Admins,CN=Users," + baseDN
}

// AdministratorsDN returns the distinguished name for Administrators group
func AdministratorsDN(baseDN string) string {
	return "CN=Administrators,CN=Builtin," + baseDN
}

// DomainControllersDN returns the distinguished name for Domain Controllers group
func DomainControllersDN(baseDN string) string {
	return "CN=Domain Controllers,CN=Users," + baseDN
}
