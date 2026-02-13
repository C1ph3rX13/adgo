package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// jsonPrinter outputs LDAP entries in JSON format.
// It supports both batch printing and streaming with metadata.
type jsonPrinter struct {
	cfg PrinterConfig
}

// newJSONPrinter creates a new JSON printer instance.
func newJSONPrinter(cfg PrinterConfig) Printer {
	return &jsonPrinter{cfg: cfg}
}

// jsonMeta contains metadata about the JSON output.
type jsonMeta struct {
	Version   string `json:"version"`   // Output format version
	Timestamp string `json:"timestamp"` // ISO 8601 timestamp of output generation
}

// jsonSummary contains summary statistics about the output.
type jsonSummary struct {
	Count int `json:"count"` // Number of entries output
}

// jsonEntry represents a single LDAP entry in JSON format.
type jsonEntry struct {
	DN         string            `json:"dn"`         // Distinguished Name of the entry
	Attributes map[string]string `json:"attributes"` // Formatted attributes as key-value pairs
}

// Print outputs LDAP entries in JSON format with metadata and summary.
// The output includes version, timestamp, entries array, and count.
func (p *jsonPrinter) Print(entries []*ldap.Entry) error {
	data := make([]jsonEntry, 0, len(entries))
	for _, e := range entries {
		data = append(data, jsonEntry{
			DN:         e.DN,
			Attributes: p.toMap(e),
		})
	}

	output := struct {
		Meta    jsonMeta    `json:"meta"`
		Data    []jsonEntry `json:"data"`
		Summary jsonSummary `json:"summary"`
	}{
		Meta: jsonMeta{
			Version:   "1.0",
			Timestamp: time.Now().Format(time.RFC3339),
		},
		Data:    data,
		Summary: jsonSummary{Count: len(entries)},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// StreamPrint writes LDAP entries to stdout in JSON format as they arrive.
// It outputs a streaming JSON structure with metadata, entries array, and summary.
func (p *jsonPrinter) StreamPrint(entriesChan <-chan *ldap.Entry) error {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	m := jsonMeta{
		Version:   "1.0",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if _, err := w.WriteString("{\n  \"meta\": "); err != nil {
		return err
	}
	if err := p.write(w, m); err != nil {
		return err
	}
	if _, err := w.WriteString(",\n  \"data\": [\n"); err != nil {
		return err
	}

	first := true
	count := 0
	for e := range entriesChan {
		if e == nil {
			continue
		}
		if !first {
			if _, err := w.WriteString(",\n"); err != nil {
				return err
			}
		}
		first = false
		count++

		if _, err := w.WriteString("    "); err != nil {
			return err
		}
		if err := p.write(w, jsonEntry{
			DN:         e.DN,
			Attributes: p.toMap(e),
		}); err != nil {
			return err
		}
	}

	if _, err := w.WriteString("\n  ],\n  \"summary\": "); err != nil {
		return err
	}
	if err := p.write(w, jsonSummary{Count: count}); err != nil {
		return err
	}
	if _, err := w.WriteString("\n}\n"); err != nil {
		return err
	}
	return w.Flush()
}

// toMap converts an LDAP entry to a map of formatted attributes.
// It uses the shared formatEntryAttributes function for consistency.
func (p *jsonPrinter) toMap(e *ldap.Entry) map[string]string {
	return formatEntryAttributes(e)
}

// write marshals a value to JSON and writes it to the buffer.
// Returns an error if marshaling or writing fails.
func (p *jsonPrinter) write(w *bufio.Writer, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	_, err = w.Write(b)
	return err
}
