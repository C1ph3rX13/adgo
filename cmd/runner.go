package cmd

import (
	"adgo/connect"
	"adgo/output"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RunQuery encapsulates the common logic for LDAP queries:
// 1. Get configuration
// 2. Initialize LDAP client
// 3. Perform search
// 4. Print results
// cmd: Cobra command context
// filter: LDAP filter string
// attributes: List of attributes to retrieve
func RunQuery(cmd *cobra.Command, filter string, attributes []string) {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// 1. Get configuration
	cfg := Get()

	// 2. Initialize LDAP client
	ldapClient, err := connect.NewClient(&cfg.LDAP)
	if err != nil {
		cmd.Printf("Error creating LDAP client: %v\n", err)
		return
	}
	defer ldapClient.Close()

	// 3. Handle Output Setup
	outputFormat, _ := cmd.Flags().GetString("output")
	if outputFormat == "" {
		outputFormat = cfg.Output
	}

	var filePath string
	if outputFormat == "csv" {
		filePath = connect.GenerateFilename(cfg.LDAP.BaseDN)
	}

	// Create printer configuration
	printerConfig := output.PrinterConfig{
		Format:   outputFormat,
		FilePath: filePath,
	}

	// Create printer using adgo/output package
	p, err := output.NewPrinter(printerConfig)
	if err != nil {
		cmd.Printf("Error creating printer: %v\n", err)
		return
	}

	// 4. Perform Streaming Search and Print
	entriesChan, errChan := ldapClient.StreamSearch(ctx, filter, attributes)

	defer func() {
		cancel()
		ldapClient.Close()
	}()

	if err := p.StreamPrint(entriesChan); err != nil {
		cmd.Printf("Error printing results: %v\n", err)
		return
	}

	if err, ok := <-errChan; ok && err != nil {
		cmd.Printf("Error executing query: %v\n", err)
		return
	}

	if filePath != "" {
		displayCSVInfo(filePath)
	}
}

// displayCSVInfo displays the CSV file path information
// filePath: Path to the generated CSV file
func displayCSVInfo(filePath string) {
	fmt.Fprintf(os.Stderr, "\nCSV file generated successfully at: %s\n", filePath)
}
