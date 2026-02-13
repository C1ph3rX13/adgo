package cmd

import (
	"adgo/analyze"
	"fmt"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "adgo",
	Short: "ADGO - Active Directory recon and triage for red team operators",
	Long:  "ADGO: Active Directory reconnaissance and triage tool for red team operators. Enumerate, triage, and export AD information.",
	// Disable completion command
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	// Disable suggestions for completion
	SuggestionsMinimumDistance: 1,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initializeConfig(cmd)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

// initializeConfig initializes and updates the configuration based on the provided command.
// It sets up viper, reads config files, binds flags, and triggers interactive setup if needed.
func initializeConfig(cmd *cobra.Command) error {
	// Initialize config (Set defaults, read config file)
	if err := InitConfig(); err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	// Note: Flags are bound in init() via BindFlags(rootCmd)
	// This ensures viper knows about the flags before parsing/unmarshaling.

	// Since flags are now bound to viper keys, we just need to reload the struct
	// to ensure 'cfg' reflects the merged state (Flags > Env > Config > Defaults).
	if err := Reload(); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Check if we need to trigger interactive setup
	// Trigger if: Server is missing, config file not found, and not running help/version/init
	if GetConfig().LDAP.Server == "" && GetConfigPath() == "" &&
		cmd.Name() != "help" && cmd.Name() != "version" && cmd.Name() != "init" {
		setup()
		// Reload after interactive setup
		if err := Reload(); err != nil {
			return fmt.Errorf("failed to reload config after interactive setup: %w", err)
		}
	}

	return nil
}

func init() {
	// Add global flags
	rootCmd.PersistentFlags().StringP("server", "s", "", "Domain Controller Host/IP")

	rootCmd.PersistentFlags().IntP("port", "p", analyze.DefaultLDAPPort, "LDAP Port")

	rootCmd.PersistentFlags().StringP("baseDN", "b", "", "Base DN (e.g., DC=Domain,DC=com)")

	rootCmd.PersistentFlags().StringP("username", "u", "", "Bind username")

	rootCmd.PersistentFlags().StringP("password", "w", "", "Bind password")

	rootCmd.PersistentFlags().StringP("output", "o", analyze.DefaultOutputFormat, "Output format (text, json, csv, bloodhound)")

	// Bind flags to viper
	BindFlags(rootCmd)
}
