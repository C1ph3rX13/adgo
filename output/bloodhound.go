package output

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	// BloodHound format version
	bloodHoundVersion = 4
)

// bloodHoundMetadata represents the metadata section of BloodHound output
type bloodHoundMetadata struct {
	Type           string `json:"type"`
	Version        int    `json:"version"`
	Count          int    `json:"count"`
	CollectionTime string `json:"collectiontime"`
}

// bloodHoundUser represents a BloodHound user object
type bloodHoundUser struct {
	Properties bloodHoundUserProps `json:"Properties"`
	ObjectID   string              `json:"ObjectIdentifier"`
	ACLs       []bloodHoundACL     `json:"Aces,omitempty"`
}

// bloodHoundUserProps represents user properties for BloodHound
type bloodHoundUserProps struct {
	Name                  string   `json:"name"`
	Domain                string   `json:"domain"`
	Enabled               bool     `json:"enabled"`
	HasSPN                bool     `json:"hasspn,omitempty"`
	ServicePrincipalNames []string `json:"serviceprincipalnames,omitempty"`
	LastLogon             int64    `json:"lastlogon,omitempty"`
	LastLogonTimestamp    int64    `json:"lastlogontimestamp,omitempty"`
	PwdLastSet            int64    `json:"pwdlastset,omitempty"`
	PasswordNotRequired   bool     `json:"passwordnotrequired,omitempty"`
	PasswordNeverExpires  bool     `json:"passwordneverexpires,omitempty"`
	AdminCount            int      `json:"admincount,omitempty"`
	DontReqPreAuth        bool     `json:"dontreqpreauth,omitempty"`
	Delegatable           bool     `json:"delegatable,omitempty"`
	UAC                   string   `json:"useraccountcontrol,omitempty"`
	SID                   string   `json:"sid,omitempty"`
	WhenCreated           string   `json:"whencreated,omitempty"`
}

// bloodHoundComputer represents a BloodHound computer object
type bloodHoundComputer struct {
	Properties bloodHoundComputerProps `json:"Properties"`
	ObjectID   string                  `json:"ObjectIdentifier"`
	ACLs       []bloodHoundACL         `json:"Aces,omitempty"`
}

// bloodHoundComputerProps represents computer properties for BloodHound
type bloodHoundComputerProps struct {
	Name               string `json:"name"`
	Domain             string `json:"domain"`
	Enabled            bool   `json:"enabled"`
	LastLogon          int64  `json:"lastlogon,omitempty"`
	LastLogonTimestamp int64  `json:"lastlogontimestamp,omitempty"`
	OperatingSystem    string `json:"operatingsystem,omitempty"`
	OSVersion          string `json:"osversion,omitempty"`
	SID                string `json:"sid,omitempty"`
	WhenCreated        string `json:"whencreated,omitempty"`
}

// bloodHoundGroup represents a BloodHound group object
type bloodHoundGroup struct {
	Properties bloodHoundGroupProps `json:"Properties"`
	ObjectID   string               `json:"ObjectIdentifier"`
	ACLs       []bloodHoundACL      `json:"Aces,omitempty"`
	Members    []string             `json:"Members,omitempty"`
}

// bloodHoundGroupProps represents group properties for BloodHound
type bloodHoundGroupProps struct {
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Enabled     bool   `json:"enabled"`
	MemberCount int    `json:"membercount,omitempty"`
	SID         string `json:"sid,omitempty"`
	WhenCreated string `json:"whencreated,omitempty"`
}

// bloodHoundACL represents an Access Control Entry in BloodHound format
type bloodHoundACL struct {
	PrincipalName string `json:"PrincipalName"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

// bloodHoundOutput represents the complete BloodHound JSON structure
type bloodHoundOutput struct {
	Meta bloodHoundMetadata `json:"meta"`
	Data []map[string]any   `json:"data"`
}

// bloodHoundPrinter outputs BloodHound JSON format
type bloodHoundPrinter struct {
	cfg        PrinterConfig
	objectType string // "users", "computers", "groups"
}

// newBloodHoundPrinter creates a new BloodHound format printer
func newBloodHoundPrinter(cfg PrinterConfig, objectType string) Printer {
	return &bloodHoundPrinter{
		cfg:        cfg,
		objectType: objectType,
	}
}

// Print outputs entries in BloodHound JSON format
func (p *bloodHoundPrinter) Print(entries []*ldap.Entry) error {
	// Convert entries to BloodHound format
	bhData := make([]map[string]any, 0, len(entries))

	// Auto-detect object type from entries
	objectType := p.autoDetectObjectType(entries)

	for _, entry := range entries {
		bhObj := p.convertToBloodHound(entry, objectType)
		if bhObj != nil {
			bhData = append(bhData, bhObj)
		}
	}

	// Create complete output structure
	output := bloodHoundOutput{
		Meta: bloodHoundMetadata{
			Type:           objectType,
			Version:        bloodHoundVersion,
			Count:          len(bhData),
			CollectionTime: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		},
		Data: bhData,
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling BloodHound JSON: %w", err)
	}

	// Write output
	if p.cfg.Path != "" {
		return os.WriteFile(p.cfg.Path, data, 0644)
	}

	fmt.Println(string(data))
	return nil
}

// autoDetectObjectType detects the primary object type from entries
func (p *bloodHoundPrinter) autoDetectObjectType(entries []*ldap.Entry) string {
	typeCount := map[string]int{"users": 0, "computers": 0, "groups": 0}

	for _, entry := range entries {
		// Prioritize using objectClass
		objectClasses := getAttributeValues(entry, "objectClass")
		if len(objectClasses) > 0 {
			// objectClass has multiple values, check by priority
			// Priority: computer > user > group
			// Most specific class should be last: "top", "person", "organizationalPerson", "user", "computer"
			if slices.Contains(objectClasses, "computer") {
				typeCount["computers"]++
			} else if slices.Contains(objectClasses, "user") {
				typeCount["users"]++
			} else if slices.Contains(objectClasses, "group") {
				typeCount["groups"]++
			}
		} else {
			// Fallback: detect type from DN when objectClass is missing
			detectedType := detectTypeFromDN(entry.DN)
			switch detectedType {
			case "DC":
				typeCount["computers"]++
			case "USER":
				typeCount["users"]++
			case "COMPUTER":
				typeCount["computers"]++
			case "GROUP":
				typeCount["groups"]++
			}
		}
	}

	// Return the type with highest count
	maxCount := 0
	detectedType := "users"
	for objType, count := range typeCount {
		if count > maxCount {
			maxCount = count
			detectedType = objType
		}
	}

	return detectedType
}

// containsClass checks if objectClass string contains a specific class
func containsClass(objectClass, class string) bool {
	// Simple substring check
	return len(objectClass) >= len(class) && indexOf(objectClass, class) >= 0
}

// indexOf finds substring in string
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// detectTypeFromDN detects object type by parsing the DN string
// This serves as a fallback when objectClass is not available
func detectTypeFromDN(dn string) string {
	switch {
	case indexOf(dn, "OU=Domain Controllers,") >= 0:
		return "DC"
	case indexOf(dn, "CN=Users,") >= 0:
		// Users container
		return "USER"
	case indexOf(dn, "CN=Computers,") >= 0:
		return "COMPUTER"
	case indexOf(dn, "CN=Groups,") >= 0:
		return "GROUP"
	default:
		// Default detection based on parent container
		if indexOf(dn, ",CN=Users,") >= 0 {
			return "USER"
		}
		// Default to COMPUTER for most other cases
		return "COMPUTER"
	}
}

// StreamPrint streams entries in BloodHound JSON format
func (p *bloodHoundPrinter) StreamPrint(entriesChan <-chan *ldap.Entry) error {
	// Collect all entries first (BloodHound JSON needs metadata)
	var entries []*ldap.Entry
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	return p.Print(entries)
}

// convertToBloodHound converts an LDAP entry to BloodHound format
func (p *bloodHoundPrinter) convertToBloodHound(entry *ldap.Entry, objectType string) map[string]any {
	// objectClass is optional - use objectType parameter for conversion
	// This allows processing entries even when objectClass attribute is missing
	switch objectType {
	case "users":
		return p.convertUser(entry)
	case "computers":
		return p.convertComputer(entry)
	case "groups":
		return p.convertGroup(entry)
	default:
		return p.convertGeneric(entry)
	}
}

// convertUser converts LDAP entry to BloodHound user format
func (p *bloodHoundPrinter) convertUser(entry *ldap.Entry) map[string]any {
	domain := extractDomain(entry.DN)

	user := bloodHoundUser{
		ObjectID: entry.DN,
		Properties: bloodHoundUserProps{
			Name:                  getAttributeValue(entry, "sAMAccountName"),
			Domain:                domain,
			Enabled:               isEnabled(entry),
			HasSPN:                hasSPN(entry),
			ServicePrincipalNames: getAttributeValues(entry, "servicePrincipalName"),
			AdminCount:            getIntAttribute(entry, "adminCount"),
			DontReqPreAuth:        getBoolAttribute(entry, "userAccountControl", "dontReqPreauth"),
			Delegatable:           getBoolAttribute(entry, "userAccountControl", "trustedToAuthForDelegation"),
			SID:                   getAttributeValue(entry, "objectSID"),
			WhenCreated:           getAttributeValue(entry, "whenCreated"),
		},
	}

	// Convert to map
	return map[string]any{
		"Properties":       user.Properties,
		"ObjectIdentifier": user.ObjectID,
	}
}

// convertComputer converts LDAP entry to BloodHound computer format
func (p *bloodHoundPrinter) convertComputer(entry *ldap.Entry) map[string]any {
	domain := extractDomain(entry.DN)

	computer := bloodHoundComputer{
		ObjectID: entry.DN,
		Properties: bloodHoundComputerProps{
			Name:            getAttributeValue(entry, "sAMAccountName"),
			Domain:          domain,
			Enabled:         isEnabled(entry),
			OperatingSystem: getAttributeValue(entry, "operatingSystem"),
			OSVersion:       getAttributeValue(entry, "operatingSystemVersion"),
			SID:             getAttributeValue(entry, "objectSID"),
			WhenCreated:     getAttributeValue(entry, "whenCreated"),
		},
	}

	return map[string]any{
		"Properties":       computer.Properties,
		"ObjectIdentifier": computer.ObjectID,
	}
}

// convertGroup converts LDAP entry to BloodHound group format
func (p *bloodHoundPrinter) convertGroup(entry *ldap.Entry) map[string]any {
	domain := extractDomain(entry.DN)

	group := bloodHoundGroup{
		ObjectID: entry.DN,
		Properties: bloodHoundGroupProps{
			Name:        getAttributeValue(entry, "sAMAccountName"),
			Domain:      domain,
			Enabled:     true, // Groups don't have disabled state
			MemberCount: len(getAttributeValues(entry, "member")),
			SID:         getAttributeValue(entry, "objectSID"),
			WhenCreated: getAttributeValue(entry, "whenCreated"),
		},
		Members: getAttributeValues(entry, "member"),
	}

	return map[string]any{
		"Properties":       group.Properties,
		"ObjectIdentifier": group.ObjectID,
		"Members":          group.Members,
	}
}

// convertGeneric creates a generic BloodHound object
func (p *bloodHoundPrinter) convertGeneric(entry *ldap.Entry) map[string]any {
	// Create a generic map-based representation
	obj := map[string]any{
		"ObjectIdentifier": entry.DN,
		"Properties": map[string]any{
			"name":   getAttributeValue(entry, "sAMAccountName"),
			"domain": extractDomain(entry.DN),
		},
	}

	// Add all attributes
	for _, attr := range entry.Attributes {
		if len(attr.Values) == 1 {
			obj["Properties"].(map[string]any)[attr.Name] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			obj["Properties"].(map[string]any)[attr.Name] = attr.Values
		}
	}

	return obj
}

// Helper functions

// getAttributeValue safely gets a single attribute value
func getAttributeValue(entry *ldap.Entry, name string) string {
	attr := entry.GetAttributeValues(name)
	if len(attr) > 0 {
		return attr[0]
	}
	return ""
}

// getAttributeValues gets all values for an attribute
func getAttributeValues(entry *ldap.Entry, name string) []string {
	values := entry.GetAttributeValues(name)
	if values == nil {
		return []string{}
	}
	return values
}

// getIntAttribute gets an integer attribute value
func getIntAttribute(entry *ldap.Entry, name string) int {
	values := entry.GetAttributeValues(name)
	if len(values) > 0 {
		// Parse int from string
		var i int
		if _, err := fmt.Sscanf(values[0], "%d", &i); err == nil {
			return i
		}
	}
	return 0
}

// extractDomain extracts domain from DN
func extractDomain(dn string) string {
	// Parse DC components from DN
	// DC=example,DC=com -> example.com
	domainParts := []string{}
	parts := splitDN(dn)
	for _, part := range parts {
		if len(part) > 3 && part[0:3] == "DC=" {
			domainParts = append(domainParts, part[3:])
		}
	}

	if len(domainParts) == 0 {
		return "UNKNOWN"
	}

	domain := domainParts[0]
	for i := 1; i < len(domainParts); i++ {
		domain += "." + domainParts[i]
	}
	return domain
}

// splitDN splits a DN into components
func splitDN(dn string) []string {
	var parts []string
	current := ""
	inEscape := false

	for i, c := range dn {
		switch {
		case inEscape:
			current += string(c)
			inEscape = false
		case c == '\\':
			inEscape = true
		case c == ',':
			parts = append(parts, current)
			current = ""
		default:
			current += string(c)
		}

		if i == len(dn)-1 && current != "" {
			parts = append(parts, current)
		}
	}

	return parts
}

// isEnabled checks if a user/computer is enabled based on UAC
func isEnabled(entry *ldap.Entry) bool {
	uac := getAttributeValue(entry, "userAccountControl")
	if uac == "" {
		return true // Default to enabled if no UAC
	}

	// Parse UAC as integer
	var uacValue int
	if _, err := fmt.Sscanf(uac, "%d", &uacValue); err != nil {
		return true
	}

	// ACCOUNTDISABLE (0x0002) = 2
	return (uacValue & 2) == 0
}

// hasSPN checks if a user has service principal names
func hasSPN(entry *ldap.Entry) bool {
	spns := entry.GetAttributeValues("servicePrincipalName")
	return len(spns) > 0
}

// getBoolAttribute checks if a specific UAC flag is set
func getBoolAttribute(entry *ldap.Entry, attrName, flagName string) bool {
	// This would need proper UAC parsing
	// For now, return false
	return false
}
