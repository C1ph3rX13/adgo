package output

import (
	"adgo/analyze"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// PrinterConfig defines configuration options for output printers.
type PrinterConfig struct {
	Format string // Output format: "text", "json", or "csv"
	Path   string // Optional file path. If empty, writes to stdout
}

// Printer defines the interface for output formatters.
// Implementations must support both batch printing and streaming of LDAP entries.
type Printer interface {
	Print(entries []*ldap.Entry) error
	StreamPrint(entriesChan <-chan *ldap.Entry) error
}

// NewPrinter creates a new Printer instance based on the specified format.
// Returns an error if the format is not supported.
//
// Supported formats:
//   - "text": Human-readable card-based output with color
//   - "json": Structured JSON output with metadata
//   - "csv": Comma-separated values for spreadsheet compatibility
//   - "bloodhound" or "bh": BloodHound JSON format for analysis
func NewPrinter(cfg PrinterConfig) (Printer, error) {
	switch cfg.Format {
	case "text", "card":
		return newTextPrinter(cfg), nil
	case "json":
		return newJSONPrinter(cfg), nil
	case "csv":
		return newCSVPrinter(cfg), nil
	case "bloodhound", "bh":
		// Default to users object type if not specified
		return newBloodHoundPrinter(cfg, "users"), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", cfg.Format)
	}
}

// formatEntryAttributes converts LDAP entry attributes to a map of attribute names to formatted values.
// It uses the analyze package to format each attribute appropriately.
// Empty or invalid attributes are omitted from the result.
func formatEntryAttributes(e *ldap.Entry) map[string]string {
	attrs := make(map[string]string)
	for _, attr := range e.Attributes {
		if v, err := analyze.FormatAttributeValue(e, attr.Name); err == nil && v != "" {
			attrs[attr.Name] = v
		}
	}
	return attrs
}
