package cmd

import (
	"github.com/spf13/cobra"
)

// queryCmd represents the query command group
var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Run a custom LDAP query (filter/attrs)",
	Long:  "Query executes a custom LDAP filter for targeted recon and returns the requested attributes.",
	Run: func(cmd *cobra.Command, args []string) {
		// Get flags
		filter, _ := cmd.Flags().GetString("filter")
		attrs, _ := cmd.Flags().GetStringSlice("attrs")

		// Use default filter if none provided
		if filter == "" {
			filter = "(objectClass=*)"
		}

		// Execute common LDAP query logic
		RunQuery(cmd, filter, attrs)
	},
}

func init() {
	rootCmd.AddCommand(queryCmd)

	queryCmd.Flags().StringP("filter", "f", "", "LDAP filter (e.g., (objectClass=user))")
	queryCmd.Flags().StringSliceP("attrs", "a", []string{"*"}, "Attributes to return (default: *)")

}
