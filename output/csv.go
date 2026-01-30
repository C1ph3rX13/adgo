package output

import (
	"adgo/analyze"
	"encoding/csv"
	"fmt"
	"os"
	"sort"

	"github.com/go-ldap/ldap/v3"
)

type CSVPrinter struct {
	Config PrinterConfig
}

func NewCSVPrinter(config PrinterConfig) Printer {
	return &CSVPrinter{
		Config: config,
	}
}

func (p *CSVPrinter) Print(entries []*ldap.Entry) error {
	if len(entries) == 0 {
		return nil
	}

	attrSet := make(map[string]bool)
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			attrSet[attr.Name] = true
		}
	}

	sortedAttrs := make([]string, 0, len(attrSet))
	for attr := range attrSet {
		sortedAttrs = append(sortedAttrs, attr)
	}
	sort.Strings(sortedAttrs)

	var writer *csv.Writer
	var file *os.File
	var err error

	if p.Config.FilePath != "" {
		file, err = os.Create(p.Config.FilePath)
		if err != nil {
			return fmt.Errorf("failed to create CSV file: %w", err)
		}
		defer file.Close()
		writer = csv.NewWriter(file)
	} else {
		writer = csv.NewWriter(os.Stdout)
	}
	defer writer.Flush()

	header := append([]string{"DN"}, sortedAttrs...)
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, entry := range entries {
		row := make([]string, len(header))
		row[0] = entry.DN

		entryAttrs := make(map[string]string)
		for _, attr := range entry.Attributes {
			val, err := analyze.FormatAttributeValue(entry, attr.Name)
			if err == nil {
				entryAttrs[attr.Name] = val
			}
		}

		for i, attr := range sortedAttrs {
			if val, ok := entryAttrs[attr]; ok {
				row[i+1] = val
			} else {
				row[i+1] = ""
			}
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (p *CSVPrinter) StreamPrint(entriesChan <-chan *ldap.Entry) error {
	var writer *csv.Writer
	var file *os.File
	var err error

	if p.Config.FilePath != "" {
		file, err = os.Create(p.Config.FilePath)
		if err != nil {
			return fmt.Errorf("failed to create CSV file: %w", err)
		}
		defer file.Close()
		writer = csv.NewWriter(file)
	} else {
		writer = csv.NewWriter(os.Stdout)
	}
	defer writer.Flush()

	header := []string{"DN (Distinguished Name)", "Attribute Name", "Attribute Value"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for entry := range entriesChan {
		if entry == nil {
			continue
		}

		attrMap := make(map[string]string)
		var attrNames []string

		for _, attr := range entry.Attributes {
			parsedValue, err := analyze.FormatAttributeValue(entry, attr.Name)
			if err == nil && parsedValue != "" {
				attrMap[attr.Name] = parsedValue
				attrNames = append(attrNames, attr.Name)
			}
		}
		sort.Strings(attrNames)

		for _, attrName := range attrNames {
			value := attrMap[attrName]

			row := make([]string, 3)
			row[0] = entry.DN
			row[1] = attrName
			row[2] = value

			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}

	return nil
}
