package output

import (
	"adgo/analyze"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/go-ldap/ldap/v3"
)

type TextPrinter struct {
	Config PrinterConfig
	red    func(a ...interface{}) string
	yellow func(a ...interface{}) string
	blue   func(a ...interface{}) string
	green  func(a ...interface{}) string
	cyan   func(a ...interface{}) string
	bold   func(a ...interface{}) string
	dim    func(a ...interface{}) string
}

func NewTextPrinter(config PrinterConfig) Printer {
	if color.NoColor {
		return &TextPrinter{
			Config: config,
			red:    fmt.Sprint,
			yellow: fmt.Sprint,
			blue:   fmt.Sprint,
			green:  fmt.Sprint,
			cyan:   fmt.Sprint,
			bold:   fmt.Sprint,
			dim:    fmt.Sprint,
		}
	}

	return &TextPrinter{
		Config: config,
		red:    color.New(color.FgRed).SprintFunc(),
		yellow: color.New(color.FgYellow).SprintFunc(),
		blue:   color.New(color.FgBlue).SprintFunc(),
		green:  color.New(color.FgGreen).SprintFunc(),
		cyan:   color.New(color.FgCyan).SprintFunc(),
		bold:   color.New(color.Bold).SprintFunc(),
		dim:    color.New(color.Faint).SprintFunc(),
	}
}

func (p *TextPrinter) Print(entries []*ldap.Entry) error {
	if len(entries) == 0 {
		fmt.Println("[INFO] No entries found")
		return nil
	}
	return p.printCard(entries)
}

func (p *TextPrinter) StreamPrint(entriesChan <-chan *ldap.Entry) error {
	return p.streamCard(entriesChan)
}

func (p *TextPrinter) printCard(entries []*ldap.Entry) error {
	p.printHeader("Search Results")
	for _, entry := range entries {
		p.printEntryCard(entry)
	}
	p.printFooter(len(entries))
	return nil
}

func (p *TextPrinter) streamCard(entriesChan <-chan *ldap.Entry) error {
	p.printHeader("Search Results")
	count := 0
	for entry := range entriesChan {
		if entry != nil {
			p.printEntryCard(entry)
			count++
		}
	}
	p.printFooter(count)
	return nil
}

func (p *TextPrinter) printEntryCard(entry *ldap.Entry) {
	attrMap := p.buildAttrMap(entry)
	objType := p.getObjectType(entry.DN)

	separator := strings.Repeat("-", 80)
	fmt.Printf("%s\n", separator)
	fmt.Printf("%s\n", p.bold(fmt.Sprintf("[%s] %s", objType, entry.DN)))
	fmt.Printf("%s\n", separator)

	var keys []string
	var maxKeyLen int
	for k := range attrMap {
		if attrMap[k] != "" {
			keys = append(keys, k)
			if len(k) > maxKeyLen {
				maxKeyLen = len(k)
			}
		}
	}
	sort.Strings(keys)

	if maxKeyLen < 20 {
		maxKeyLen = 20
	}
	if maxKeyLen > 50 {
		maxKeyLen = 50
	}

	for _, k := range keys {
		val := attrMap[k]
		if k == "whenCreated" || k == "whenChanged" {
			val = p.formatTime(val)
		}
		if val != "" {
			val = strings.ReplaceAll(val, "\r\n", " ")
			val = strings.ReplaceAll(val, "\n", " ")
			val = strings.ReplaceAll(val, "\r", " ")
			val = strings.ReplaceAll(val, "\t", " ")
		}

		keyText := fmt.Sprintf("  [*] %s", k)
		keyStr := p.cyan(keyText)
		padding := strings.Repeat(" ", maxKeyLen-len(k))
		valStr := val

		if strings.Contains(k, "AllowedToDelegate") ||
			strings.Contains(k, "AllowedToAct") ||
			(k == "adminCount" && val == "1") ||
			(k == "userAccountControl" && (strings.Contains(val, "Domain Controller") || strings.Contains(val, "Trust") || strings.Contains(val, "Krbtgt"))) {
			valStr = p.red(val)
		} else if k == "whenCreated" || k == "whenChanged" {
			valStr = p.dim(val)
		}

		keyIndent := strings.Repeat(" ", len([]rune(keyText))+len(padding)+3)

		if k == "nTSecurityDescriptor" || strings.HasPrefix(valStr, "Owner=") || strings.HasPrefix(valStr, "O:") {
			for i, part := range wrapRunes(valStr, 120) {
				if i == 0 {
					fmt.Printf("%s%s : %s\n", keyStr, padding, part)
					continue
				}
				fmt.Printf("%s%s\n", keyIndent, part)
			}
			continue
		}

		if len(valStr) > 120 {
			valStr = valStr[:117] + "..."
		}

		fmt.Printf("%s%s : %s\n", keyStr, padding, valStr)
	}
	fmt.Println()
}

func wrapRunes(s string, width int) []string {
	if width <= 0 || s == "" {
		return []string{s}
	}
	if !utf8.ValidString(s) {
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

func (p *TextPrinter) printHeader(title string) {
	fmt.Println()
	fmt.Printf("  %s\n", p.cyan(fmt.Sprintf("ADGO REPORT  |  %s", title)))
	fmt.Println()
}

func (p *TextPrinter) printFooter(count int) {
	fmt.Printf("Total Entries: %s\n", p.green(strconv.Itoa(count)))
}

func (p *TextPrinter) buildAttrMap(entry *ldap.Entry) map[string]string {
	attrMap := make(map[string]string)
	for _, attr := range entry.Attributes {
		parsedValue, err := analyze.FormatAttributeValue(entry, attr.Name)
		if err == nil && parsedValue != "" {
			attrMap[attr.Name] = parsedValue
		} else {
			attrMap[attr.Name] = ""
		}
	}
	return attrMap
}

func (p *TextPrinter) getObjectType(dn string) string {
	if strings.Contains(dn, "OU=Domain Controllers,") {
		return "DC"
	} else if strings.Contains(dn, "CN=Computers,") {
		return "COMPUTER"
	} else if strings.Contains(dn, "CN=Users,") || strings.Contains(dn, "OU=Users,") {
		return "USER"
	} else if strings.Contains(dn, "CN=Groups,") || strings.Contains(dn, "OU=Groups,") {
		return "GROUP"
	} else if strings.Contains(dn, "OU=") {
		return "OU"
	}
	return "OTHER"
}

func (p *TextPrinter) formatTime(val string) string {
	if val == "" {
		return ""
	}
	layout := "20060102150405.0Z"
	t, err := time.Parse(layout, val)
	if err != nil {
		return val
	}
	return t.Format("2006-01-02 15:04:05")
}
