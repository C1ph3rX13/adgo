package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"

	"github.com/go-ldap/ldap/v3"
)

// csvPrinter outputs LDAP entries in CSV format.
// It supports both batch (wide format) and streaming (long format) output.
type csvPrinter struct {
	cfg PrinterConfig
}

// newCSVPrinter creates a new CSV printer instance.
func newCSVPrinter(cfg PrinterConfig) Printer {
	return &csvPrinter{cfg: cfg}
}

// Print outputs LDAP entries in CSV wide format (one row per entry).
// All attributes from all entries are collected and used as columns.
func (p *csvPrinter) Print(entries []*ldap.Entry) error {
	if len(entries) == 0 {
		return nil
	}

	attrs := p.collectAttrs(entries)
	writer, closeFn, err := p.createWriter()
	if err != nil {
		return err
	}
	defer closeFn()

	header := append([]string{"DN"}, attrs...)
	if err := writer.Write(header); err != nil {
		return err
	}
	writer.Flush() // Ensure header is written immediately

	for _, entry := range entries {
		row := p.buildRow(entry, header)
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// StreamPrint outputs LDAP entries in CSV long format as they arrive (one row per attribute).
// Each row contains: DN, attribute name, attribute value.
func (p *csvPrinter) StreamPrint(entriesChan <-chan *ldap.Entry) error {
	writer, closeFn, err := p.createWriter()
	if err != nil {
		return err
	}
	defer closeFn()

	header := []string{"DN (Distinguished Name)", "Attribute Name", "Attribute Value"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}
	writer.Flush() // Ensure header is written immediately

	for entry := range entriesChan {
		if entry == nil {
			continue
		}
		if err := p.writeEntry(writer, entry); err != nil {
			return err
		}
		writer.Flush() // Flush after each entry to ensure data is written
	}

	return nil
}

// collectAttrs collects all unique attribute names from a slice of LDAP entries.
// Returns a sorted list of attribute names for use as CSV headers.
func (p *csvPrinter) collectAttrs(entries []*ldap.Entry) []string {
	attrSet := make(map[string]bool)
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			attrSet[attr.Name] = true
		}
	}

	attrs := make([]string, 0, len(attrSet))
	for attr := range attrSet {
		attrs = append(attrs, attr)
	}
	sort.Strings(attrs)
	return attrs
}

// buildRow constructs a CSV row for an entry using the provided header.
// It uses formatEntryAttributes for consistent attribute formatting.
func (p *csvPrinter) buildRow(entry *ldap.Entry, header []string) []string {
	row := make([]string, len(header))
	row[0] = entry.DN

	attrVals := formatEntryAttributes(entry)

	for i, attr := range header[1:] {
		row[i+1] = attrVals[attr]
	}

	return row
}

// writeEntry writes an LDAP entry to CSV in long format (one row per attribute).
// Each row contains: DN, attribute name, attribute value.
func (p *csvPrinter) writeEntry(writer *csv.Writer, entry *ldap.Entry) error {
	attrs := formatEntryAttributes(entry)

	// Extract and sort attribute names for consistent output
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		row := []string{entry.DN, name, attrs[name]}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// createWriter creates a CSV writer and a cleanup function.
// If Path is empty, writes to stdout. Otherwise, creates/overwrites the specified file.
// The returned cleanup function flushes and closes the writer/file.
func (p *csvPrinter) createWriter() (*csv.Writer, func(), error) {
	if p.cfg.Path == "" {
		writer := csv.NewWriter(os.Stdout)
		return writer, func() {
			writer.Flush()
			if err := writer.Error(); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing CSV writer: %v\n", err)
			}
		}, nil
	}

	file, err := os.Create(p.cfg.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSV file: %w", err)
	}

	writer := csv.NewWriter(file)
	return writer, func() {
		writer.Flush()
		if err := writer.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "Error flushing CSV writer: %v\n", err)
		}
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing CSV file: %v\n", err)
		}
	}, nil
}
