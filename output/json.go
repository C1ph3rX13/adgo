package output

import (
	"adgo/analyze"
	"bufio"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type JSONPrinter struct {
	Config PrinterConfig
}

func NewJSONPrinter(config PrinterConfig) Printer {
	return &JSONPrinter{
		Config: config,
	}
}

type jsonMeta struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

type jsonSummary struct {
	Count int `json:"count"`
}

type jsonEntry struct {
	DN         string            `json:"dn"`
	Attributes map[string]string `json:"attributes"`
}

func (p *JSONPrinter) Print(entries []*ldap.Entry) error {
	data := make([]jsonEntry, 0, len(entries))

	for _, entry := range entries {
		attrMap := make(map[string]string)

		for _, attr := range entry.Attributes {
			parsedValue, err := analyze.FormatAttributeValue(entry, attr.Name)
			if err == nil && parsedValue != "" {
				attrMap[attr.Name] = parsedValue
			} else {
				attrMap[attr.Name] = ""
			}
		}

		data = append(data, jsonEntry{
			DN:         entry.DN,
			Attributes: attrMap,
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
		Data: data,
		Summary: jsonSummary{
			Count: len(entries),
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func writeString(w io.Writer, s string) error {
	_, err := io.WriteString(w, s)
	return err
}

func marshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	b, err := json.MarshalIndent(v, prefix, indent)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (p *JSONPrinter) StreamPrint(entriesChan <-chan *ldap.Entry) error {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	meta := jsonMeta{
		Version:   "1.0",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	metaBytes, err := marshalIndent(meta, "  ", "  ")
	if err != nil {
		return err
	}

	if err := writeString(w, "{\n"); err != nil {
		return err
	}
	if err := writeString(w, `  "meta": `); err != nil {
		return err
	}
	if _, err := w.Write(metaBytes); err != nil {
		return err
	}
	if err := writeString(w, ",\n"); err != nil {
		return err
	}
	if err := writeString(w, `  "data": [`+"\n"); err != nil {
		return err
	}

	first := true
	count := 0

	for entry := range entriesChan {
		if entry == nil {
			continue
		}
		if !first {
			os.Stdout.WriteString(",\n")
		}
		first = false
		count++

		attrMap := make(map[string]string)
		for _, attr := range entry.Attributes {
			parsedValue, err := analyze.FormatAttributeValue(entry, attr.Name)
			if err == nil && parsedValue != "" {
				attrMap[attr.Name] = parsedValue
			} else {
				attrMap[attr.Name] = ""
			}
		}

		entryData := jsonEntry{
			DN:         entry.DN,
			Attributes: attrMap,
		}

		entryBytes, err := marshalIndent(entryData, "    ", "  ")
		if err != nil {
			return err
		}
		if _, err := w.Write(entryBytes); err != nil {
			return err
		}
	}

	if err := writeString(w, "\n  ],\n"); err != nil {
		return err
	}

	summary := jsonSummary{Count: count}
	summaryBytes, err := marshalIndent(summary, "  ", "  ")
	if err != nil {
		return err
	}

	if err := writeString(w, `  "summary": `); err != nil {
		return err
	}
	if _, err := w.Write(summaryBytes); err != nil {
		return err
	}

	if err := writeString(w, "}\n"); err != nil {
		return err
	}
	return w.Flush()
}
