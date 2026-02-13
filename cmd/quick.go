package cmd

import (
	"adgo/log"
	"adgo/queries"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Command categories
const (
	CategoryBasic       = "Basic Queries"
	CategoryAdmin       = "Admin Queries"
	CategoryKerberos    = "Kerberos Attacks"
	CategoryDelegation  = "Delegation"
	CategoryADCS        = "AD CS"
	CategoryPermissions = "Permissions"
)

// CommandMetadata holds the metadata for a quick query command
type CommandMetadata struct {
	Name        string
	Description string
	Category    string
}

// commandMetadata contains metadata for all predefined quick query commands
var commandMetadata = []CommandMetadata{
	// Basic Queries
	{Name: "users", Description: "All user accounts", Category: CategoryBasic},
	{Name: "computers", Description: "All computer accounts", Category: CategoryBasic},
	{Name: "dc", Description: "All domain controllers", Category: CategoryBasic},
	{Name: "ou", Description: "All organizational units", Category: CategoryBasic},
	{Name: "spn", Description: "All service principal names", Category: CategoryBasic},
	{Name: "gpo", Description: "All group policy objects", Category: CategoryBasic},
	{Name: "gpomachine", Description: "GPOs with machine settings", Category: CategoryBasic},
	{Name: "gpouser", Description: "GPOs with user settings", Category: CategoryBasic},
	{Name: "trustDomain", Description: "Trusted domains", Category: CategoryBasic},
	{Name: "trustattributes", Description: "Trusted domain attributes", Category: CategoryBasic},
	{Name: "machineAccountQuota", Description: "Machine account quota for the domain", Category: CategoryBasic},

	// Admin Queries
	{Name: "admin", Description: "All admin accounts and groups", Category: CategoryAdmin},
	{Name: "domainadmins", Description: "Domain admin group members", Category: CategoryAdmin},
	{Name: "enterprise", Description: "Enterprise related information", Category: CategoryAdmin},
	{Name: "enterpriseadmins", Description: "Enterprise admin group members", Category: CategoryAdmin},
	{Name: "schemaadmins", Description: "Schema admin group members", Category: CategoryAdmin},
	{Name: "adminSDHolder", Description: "Accounts with AdminSDHolder protection", Category: CategoryAdmin},
	{Name: "adminholders", Description: "Admin account holders", Category: CategoryAdmin},
	{Name: "sensitivegroups", Description: "Sensitive AD groups", Category: CategoryAdmin},
	{Name: "disabled", Description: "Disabled user accounts", Category: CategoryAdmin},

	// Kerberos Attacks
	{Name: "kerberoasting", Description: "Accounts vulnerable to Kerberoasting", Category: CategoryKerberos},
	{Name: "asreproast", Description: "Accounts vulnerable to AS-REP roasting", Category: CategoryKerberos},

	// Delegation
	{Name: "delegate", Description: "Accounts with delegation rights", Category: CategoryDelegation},
	{Name: "unconstraineddelegate", Description: "Accounts with unconstrained delegation", Category: CategoryDelegation},
	{Name: "constraineddelegate", Description: "Accounts with constrained delegation", Category: CategoryDelegation},
	{Name: "resourceconstraineddelegate", Description: "Accounts with resource constrained delegation", Category: CategoryDelegation},

	// AD CS
	{Name: "caComputer", Description: "Certificate authorities", Category: CategoryADCS},
	{Name: "esc1", Description: "ESC1 vulnerable certificate templates", Category: CategoryADCS},
	{Name: "esc2", Description: "ESC2 vulnerable certificate templates", Category: CategoryADCS},

	// Permissions
	{Name: "permissions", Description: "Account permissions", Category: CategoryPermissions},
	{Name: "highpriv", Description: "High privilege accounts", Category: CategoryPermissions},
	{Name: "group", Description: "Admin groups", Category: CategoryPermissions},
	{Name: "groupnested", Description: "Nested groups", Category: CategoryPermissions},
	{Name: "managedby", Description: "Objects with managedBy attribute", Category: CategoryPermissions},
	{Name: "acl", Description: "Objects with ACLs", Category: CategoryPermissions},
	{Name: "sidhistory", Description: "Accounts with SID history", Category: CategoryPermissions},
}

// getCommandCategory returns the category for a given query name
func getCommandCategory(queryName string) string {
	for _, meta := range commandMetadata {
		if meta.Name == queryName {
			return meta.Category
		}
	}
	return CategoryBasic // Default category
}

// getCommandDescription returns the description for a given query name
func getCommandDescription(queryName string) string {
	for _, meta := range commandMetadata {
		if meta.Name == queryName {
			return meta.Description
		}
	}
	return fmt.Sprintf("Run query: %s", queryName) // Default description
}

// quickCmd represents the quick command group
var quickCmd = &cobra.Command{
	Use:   "quick",
	Short: "Quick predefined queries for common AD information",
	Long:  "Quick commands provide predefined queries for common Active Directory information gathering tasks.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(quickCmd)

	// Add quick subcommands for all predefined queries
	addQuickSubcommands()

	// Override the help function to display categorized commands
	quickCmd.SetHelpFunc(customQuickHelpFunc)
}

// addQuickSubcommands adds all quick subcommands based on predefined queries
func addQuickSubcommands() {
	for _, name := range queries.GetNames() {
		use := simplifyCommandName(name)
		aliases := []string{name}

		// Get description for this command
		desc := getCommandDescription(name)

		// Standard query command creation
		cmd := &cobra.Command{
			Use:     use,
			Aliases: aliases,
			Short:   desc,
			Long:    desc,
			Run: func(cmd *cobra.Command, args []string) {
				standardQueryHandler(cmd)
			},
		}
		cmd.Annotations = map[string]string{"query": name}

		quickCmd.AddCommand(cmd)
	}
}

// printFlagsAligned prints flags with aligned descriptions
func printFlagsAligned(out io.Writer, flags *pflag.FlagSet) {
	// Calculate maximum flag string length
	maxLen := 0
	flags.VisitAll(func(flag *pflag.Flag) {
		var flagStr string
		if flag.Shorthand != "" {
			flagStr = fmt.Sprintf("-%s, --%s", flag.Shorthand, flag.Name)
		} else {
			flagStr = fmt.Sprintf("      --%s", flag.Name)
		}
		if len(flagStr) > maxLen {
			maxLen = len(flagStr)
		}
	})

	// Print flags with aligned descriptions
	flags.VisitAll(func(flag *pflag.Flag) {
		var flagStr string
		if flag.Shorthand != "" {
			flagStr = fmt.Sprintf("-%s, --%s", flag.Shorthand, flag.Name)
		} else {
			flagStr = fmt.Sprintf("      --%s", flag.Name)
		}
		// Calculate padding
		padding := maxLen - len(flagStr) + 2
		// Print with aligned description
		fmt.Fprintf(out, "  %s%s%s\n", flagStr, strings.Repeat(" ", padding), flag.Usage)
	})
}

// customQuickHelpFunc displays the help message with categorized commands
func customQuickHelpFunc(cmd *cobra.Command, args []string) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n", cmd.Long)
	fmt.Fprintf(cmd.OutOrStdout(), "Usage:\n  %s\n\n", cmd.UseLine())

	// Get all subcommands
	subcommands := cmd.Commands()

	// Group commands by category
	categoryCommands := make(map[string][]string)
	for _, subcmd := range subcommands {
		// Get the query name from annotations
		queryName := subcmd.Annotations["query"]
		if queryName == "" {
			continue
		}

		// Get category for this command
		category := getCommandCategory(queryName)

		// Add command to category
		categoryCommands[category] = append(categoryCommands[category], fmt.Sprintf("  %-30s %s", subcmd.Use, subcmd.Short))
	}

	// Display commands by category
	fmt.Fprintf(cmd.OutOrStdout(), "Available Commands:\n")

	// Define category order
	categories := []string{CategoryBasic, CategoryAdmin, CategoryKerberos, CategoryDelegation, CategoryADCS, CategoryPermissions}

	for _, category := range categories {
		if cmds, ok := categoryCommands[category]; ok && len(cmds) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "\n  %s:\n", category)
			// Sort commands alphabetically
			sort.Strings(cmds)
			for _, cmdLine := range cmds {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cmdLine)
			}
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nFlags:\n")
	printFlagsAligned(cmd.OutOrStdout(), cmd.Flags())

	fmt.Fprintf(cmd.OutOrStdout(), "\nGlobal Flags:\n")
	printFlagsAligned(cmd.OutOrStdout(), cmd.PersistentFlags())

	fmt.Fprintf(cmd.OutOrStdout(), "\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
}

// specialCaseNames maps query names to their simplified command names
// Only contains truly exceptional cases that don't follow the standard rules.
// Standard rules:
//   - Pure acronyms (2-3 chars, all caps or lowercase) → uppercase
//   - Underscore-separated → PascalCase
//   - camelCase → Capitalize first letter
var specialCaseNames = map[string]string{
	// These are truly exceptional cases that don't follow the standard patterns
	"asreproast":  "ASRepRoast",   // Capitalizes "Rep" which is non-standard
	"cacomputer":  "CaComputer",   // Lowercase "a" instead of "A"
	"gpomachine":  "GpoMachine",   // Lowercase "po" instead of "PO"
	"gpouser":     "GpoUser",      // Lowercase "po" instead of "PO"
}

// pureAcronyms are uppercase-only command names (all caps, typically 2-3 chars)
var pureAcronyms = map[string]bool{
	"dc":      true,
	"gpo":     true,
	"spn":     true,
	"ou":      true,
	"acl":     true,
	"esc1":    true,
	"esc2":    true,
}

// simplifyCommandName generates a simplified command name from the query name.
// Rules applied in order:
// 1. Check special case mappings (for truly exceptional cases)
// 2. Pure acronyms → UPPERCASE
// 3. Underscore-separated → PascalCase (each part capitalized)
// 4. camelCase/lowercase → Capitalize first letter
func simplifyCommandName(name string) string {
	// Handle special cases with direct mappings
	if simplified, ok := specialCaseNames[name]; ok {
		return simplified
	}

	// Pure acronyms → UPPERCASE
	if pureAcronyms[name] {
		return strings.ToUpper(name)
	}

	// If name has underscores, capitalize each part
	if strings.Contains(name, "_") {
		parts := strings.Split(name, "_")
		for i, part := range parts {
			if len(part) > 0 {
				parts[i] = strings.ToUpper(part[:1]) + part[1:]
			}
		}
		return strings.Join(parts, "")
	}

	// Handle camelCase and lowercase names - capitalize first letter
	if len(name) > 0 {
		return strings.ToUpper(name[:1]) + name[1:]
	}

	return name
}

// isUpper checks if a rune is an uppercase letter
func isUpper(r rune) bool {
	return r >= 'A' && r <= 'Z'
}

// standardQueryHandler handles the execution of standard LDAP queries
func standardQueryHandler(cmd *cobra.Command) {
	// Get the query name from the command annotation
	queryName := cmd.Annotations["query"]
	if queryName == "" {
		queryName = cmd.Use
	}

	// Get query definition
	q, ok := queries.Get(queryName)
	if !ok {
		log.Errorf("query '%s' not found", queryName)
		return
	}

	// Execute common LDAP query logic
	if err := RunQuery(cmd, q.Filter, q.Attributes); err != nil {
		log.Error(err)
	}
}
