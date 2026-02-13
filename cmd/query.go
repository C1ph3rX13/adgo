package cmd

import (
	"adgo/log"

	"github.com/spf13/cobra"
)

// queryCmd represents the query command group
var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Run a custom LDAP query (filter/attrs)",
	Long:  "Query executes a custom LDAP filter for targeted recon and returns the requested attributes.",
	Run: func(cmd *cobra.Command, args []string) {
		// Get flags
		filter, err := cmd.Flags().GetString("filter")
		if err != nil {
			log.Error(err)
			return
		}
		attrs, err := cmd.Flags().GetStringSlice("attrs")
		if err != nil {
			log.Error(err)
			return
		}

		// Use default filter if none provided
		if filter == "" {
			filter = "(objectClass=*)"
		}

		// Execute common LDAP query logic
		if err := RunQuery(cmd, filter, attrs); err != nil {
			log.Error(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(queryCmd)

	queryCmd.Flags().StringP("filter", "f", "", "LDAP filter (e.g., (objectClass=user))")
	queryCmd.Flags().StringSliceP("attrs", "a", []string{"*"}, "Attributes to return (default: *)")

}
