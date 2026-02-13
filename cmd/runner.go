package cmd

import (
	"adgo/connect"
	"adgo/log"
	"adgo/output"
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

// RunQuery executes an LDAP query with the given filter and attributes.
// It encapsulates the common logic for all queries:
// 1. Get configuration
// 2. Initialize LDAP client
// 3. Perform streaming search
// 4. Print results using configured format
//
// The cmd parameter provides Cobra command context (for flags and output).
// The filter is the LDAP search filter string.
// The attributes are the LDAP attributes to retrieve.
//
// Returns an error if any step fails.
func RunQuery(cmd *cobra.Command, filter string, attributes []string) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// 1. Get configuration
	cfg := GetConfig()

	// 2. Initialize LDAP client
	ldapClient, err := connect.NewClient(&cfg.LDAP)
	if err != nil {
		return fmt.Errorf("creating LDAP client: %w", err)
	}
	defer ldapClient.Close()

	// 3. Handle Output Setup
	format, _ := cmd.Flags().GetString("output")
	if format == "" {
		format = cfg.Output
	}

	var csvPath string
	if format == "csv" {
		csvPath = connect.GenerateFilename(cfg.LDAP.BaseDN)
	}

	// Create printer
	printer, err := output.NewPrinter(output.PrinterConfig{
		Format: format,
		Path:   csvPath,
	})
	if err != nil {
		return fmt.Errorf("creating printer: %v", err)
	}

	// 4. Perform Streaming Search and Print
	entriesChan, errChan := ldapClient.StreamSearch(ctx, filter, attributes)

	if err := printer.StreamPrint(entriesChan); err != nil {
		return fmt.Errorf("printing results: %v", err)
	}

	if err := <-errChan; err != nil {
		return fmt.Errorf("executing query: %v", err)
	}

	if csvPath != "" {
		log.Infof("CSV file generated: %s", csvPath)
	}

	return nil
}
