package output

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// Text output formatting constants
const (
	// Card formatting
	cardSeparatorWidth = 80  // Width of the separator line between cards
	tableSeparator     = "=" // Separator character for summary tables

	// Layout and sizing
	defaultKeyLength = 20  // Default maximum key length for padding
	maxKeyLength     = 50  // Maximum key length to consider for padding
	maxLineWidth     = 120 // Maximum line width before wrapping
	truncateLength   = 117 // Length at which to truncate and add "..."

	// Output messages
	msgNoEntries = "[INFO] No entries found"
	reportTitle  = "ADGO REPORT"
)

// Statistics holds summary statistics about entries.
type Statistics struct {
	Total    int
	Admins   int
	SPN      int
	ASRep    int
	DCs      int
	Enabled  int
	Disabled int
}

type textPrinter struct {
	cfg    PrinterConfig
	colors colorFunctions
}

func newTextPrinter(cfg PrinterConfig) Printer {
	return &textPrinter{
		cfg:    cfg,
		colors: initColors(),
	}
}

// Print outputs LDAP entries in card-based text format.
// Each entry is displayed as a separate card with attributes.
func (p *textPrinter) Print(entries []*ldap.Entry) error {
	if len(entries) == 0 {
		fmt.Println(msgNoEntries)
		return nil
	}
	return p.printCards(entries)
}

// StreamPrint outputs LDAP entries in card-based text format as they arrive.
func (p *textPrinter) StreamPrint(entriesChan <-chan *ldap.Entry) error {
	return p.streamCards(entriesChan)
}

// printCards prints multiple LDAP entry cards.
func (p *textPrinter) printCards(entries []*ldap.Entry) error {
	p.header("Search Results")

	// Collect statistics
	stats := collectStats(entries)

	// Sort entries by value (high-value targets first)
	sortedEntries := sortByValue(entries)

	// Print cards
	for _, entry := range sortedEntries {
		p.card(entry)
	}

	// Print statistics summary
	p.printSummary(stats)

	return nil
}

func (p *textPrinter) streamCards(entriesChan <-chan *ldap.Entry) error {
	p.header("Search Results")
	var entries []*ldap.Entry
	count := 0
	for entry := range entriesChan {
		if entry != nil {
			entries = append(entries, entry)
			count++
		}
	}

	// Collect statistics and sort
	stats := collectStats(entries)
	sortedEntries := sortByValue(entries)

	// Print cards
	for _, entry := range sortedEntries {
		p.card(entry)
	}

	p.printSummary(stats)
	return nil
}

func (p *textPrinter) card(entry *ldap.Entry) {
	attrs := p.toMap(entry)
	objType := objectType(entry.DN)

	sep := strings.Repeat("-", cardSeparatorWidth)
	fmt.Printf("%s\n%s\n%s\n", sep, p.colors.Bold(fmt.Sprintf("[%s] %s", objType, entry.DN)), sep)

	keys, maxLen := p.sortKeys(attrs)
	for _, k := range keys {
		p.attr(k, attrs[k], maxLen)
	}
	fmt.Println()
}

// toMap converts an LDAP entry to a map of formatted attributes.
// It uses the shared formatEntryAttributes function for consistency.
func (p *textPrinter) toMap(entry *ldap.Entry) map[string]string {
	return formatEntryAttributes(entry)
}

// sortKeys extracts and sorts attribute keys, calculating the maximum key length for padding.
func (p *textPrinter) sortKeys(attrs map[string]string) ([]string, int) {
	var keys []string
	maxLen := defaultKeyLength
	for k := range attrs {
		keys = append(keys, k)
		if len(k) > maxLen && len(k) <= maxKeyLength {
			maxLen = len(k)
		}
	}
	sort.Strings(keys)
	return keys, maxLen
}

// attr prints a single attribute with proper formatting and coloring.
func (p *textPrinter) attr(name, val string, maxKeyLen int) {
	// Note: Time formatting is already handled by analyze.FormatAttributeValue
	val = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(val)

	keyText := fmt.Sprintf("  [*] %s", name)
	keyStr := p.colors.Cyan(keyText)
	padding := strings.Repeat(" ", maxKeyLen-len(name))

	valStr := p.colorize(name, val)

	if p.isMultiline(name, valStr) {
		p.printMultiline(keyStr, padding, valStr, len(keyText)+maxKeyLen-len(name)+3)
		return
	}

	if len(valStr) > maxLineWidth {
		valStr = valStr[:truncateLength] + "..."
	}
	fmt.Printf("%s%s : %s\n", keyStr, padding, valStr)
}

// colorize applies color formatting to attribute values based on sensitivity and type.
func (p *textPrinter) colorize(name, val string) string {
	if p.isSensitive(name, val) {
		return p.colors.Red(val)
	}
	if name == "whenCreated" || name == "whenChanged" {
		return p.colors.Dim(val)
	}
	return val
}

// isSensitive checks if an attribute-value pair represents sensitive security information.
func (p *textPrinter) isSensitive(name, val string) bool {
	return strings.Contains(name, "AllowedToDelegate") ||
		strings.Contains(name, "AllowedToAct") ||
		(name == "adminCount" && val == "1") ||
		(name == "userAccountControl" && (strings.Contains(val, "Domain Controller") ||
			strings.Contains(val, "Trust") || strings.Contains(val, "Krbtgt")))
}

// isMultiline checks if an attribute value should be displayed in multiline format.
func (p *textPrinter) isMultiline(name, val string) bool {
	return name == "nTSecurityDescriptor" || strings.HasPrefix(val, "Owner=") || strings.HasPrefix(val, "O:")
}

// printMultiline prints a multi-line attribute value with proper indentation.
func (p *textPrinter) printMultiline(keyStr, padding, val string, indentLen int) {
	indent := strings.Repeat(" ", indentLen)
	for i, part := range wrap(val, maxLineWidth) {
		if i == 0 {
			fmt.Printf("%s%s : %s\n", keyStr, padding, part)
		} else {
			fmt.Printf("%s%s\n", indent, part)
		}
	}
}

// wrap splits a string into multiple lines at the specified width.
// It handles UTF-8 characters correctly and preserves word boundaries.
func wrap(s string, width int) []string {
	if width <= 0 || s == "" || !utf8.ValidString(s) {
		return []string{s}
	}
	r := []rune(s)
	if len(r) <= width {
		return []string{s}
	}

	parts := make([]string, 0, (len(r)/width)+1)
	for i := 0; i < len(r); i += width {
		end := i + width
		if end > len(r) {
			end = len(r)
		}
		parts = append(parts, string(r[i:end]))
	}
	return parts
}

// header prints the report header with the specified title.
func (p *textPrinter) header(title string) {
	fmt.Printf("\n  %s\n\n", p.colors.Cyan(fmt.Sprintf("%s  |  %s", reportTitle, title)))
}

// footer prints the report footer with entry count.
func (p *textPrinter) footer(count int) {
	fmt.Printf("Total Entries: %s\n", p.colors.Green(strconv.Itoa(count)))
}

// printSummary prints the statistics summary at the end of card output.
func (p *textPrinter) printSummary(stats Statistics) {
	fmt.Printf("\n%s\n", p.colors.Dim(strings.Repeat(tableSeparator, 80)))
	fmt.Printf("%s\n", p.colors.Bold("Summary:"))

	if stats.Admins > 0 {
		fmt.Printf("  [%s] Admins: %s\n", p.colors.Red("!"), p.colors.Red(strconv.Itoa(stats.Admins)))
	}
	if stats.SPN > 0 {
		fmt.Printf("  [*] SPN Accounts: %s (Kerberoast targets)\n", p.colors.Green(strconv.Itoa(stats.SPN)))
	}
	if stats.ASRep > 0 {
		fmt.Printf("  [*] AS-REP Roastable: %s\n", p.colors.Yellow(strconv.Itoa(stats.ASRep)))
	}
	if stats.DCs > 0 {
		fmt.Printf("  [*] Domain Controllers: %s\n", p.colors.Yellow(strconv.Itoa(stats.DCs)))
	}

	fmt.Printf("  Total: %s | Enabled: %s | Disabled: %s\n",
		p.colors.Green(strconv.Itoa(stats.Total)),
		p.colors.Green(strconv.Itoa(stats.Enabled)),
		p.colors.Yellow(strconv.Itoa(stats.Disabled)),
	)
	fmt.Printf("%s\n\n", p.colors.Dim(strings.Repeat(tableSeparator, 80)))
}
