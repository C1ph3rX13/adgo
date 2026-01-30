package cmd

import (
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

// commandCategoryMap maps query names to categories
var commandCategoryMap = map[string]string{
	"users":                       CategoryBasic,
	"computers":                   CategoryBasic,
	"dc":                          CategoryBasic,
	"ou":                          CategoryBasic,
	"spn":                         CategoryBasic,
	"gpo":                         CategoryBasic,
	"gpomachine":                  CategoryBasic,
	"gpouser":                     CategoryBasic,
	"trustDomain":                 CategoryBasic,
	"trustattributes":             CategoryBasic,
	"machineAccountQuota":         CategoryBasic,
	"admin":                       CategoryAdmin,
	"domainadmins":                CategoryAdmin,
	"enterprise":                  CategoryAdmin,
	"enterpriseadmins":            CategoryAdmin,
	"schemaadmins":                CategoryAdmin,
	"adminSDHolder":               CategoryAdmin,
	"adminholders":                CategoryAdmin,
	"sensitivegroups":             CategoryAdmin,
	"disabled":                    CategoryAdmin,
	"kerberoasting":               CategoryKerberos,
	"asreproast":                  CategoryKerberos,
	"delegate":                    CategoryDelegation,
	"unconstraineddelegate":       CategoryDelegation,
	"constraineddelegate":         CategoryDelegation,
	"resourceconstraineddelegate": CategoryDelegation,
	"caComputer":                  CategoryADCS,
	"esc1":                        CategoryADCS,
	"esc2":                        CategoryADCS,
	"permissions":                 CategoryPermissions,
	"highpriv":                    CategoryPermissions,
	"group":                       CategoryPermissions,
	"groupnested":                 CategoryPermissions,
	"managedby":                   CategoryPermissions,
	"acl":                         CategoryPermissions,
	"sidhistory":                  CategoryPermissions,
}

// commandDescriptionMap maps query names to descriptive short descriptions
var commandDescriptionMap = map[string]string{
	"users":                       "All user accounts",
	"computers":                   "All computer accounts",
	"dc":                          "All domain controllers",
	"ou":                          "All organizational units",
	"spn":                         "All service principal names",
	"gpo":                         "All group policy objects",
	"gpomachine":                  "GPOs with machine settings",
	"gpouser":                     "GPOs with user settings",
	"admin":                       "All admin accounts and groups",
	"domainadmins":                "Domain admin group members",
	"enterprise":                  "Enterprise related information",
	"enterpriseadmins":            "Enterprise admin group members",
	"schemaadmins":                "Schema admin group members",
	"adminSDHolder":               "Accounts with AdminSDHolder protection",
	"adminholders":                "Admin account holders",
	"sensitivegroups":             "Sensitive AD groups",
	"disabled":                    "Disabled user accounts",
	"kerberoasting":               "Accounts vulnerable to Kerberoasting",
	"asreproast":                  "Accounts vulnerable to AS-REP roasting",
	"delegate":                    "Accounts with delegation rights",
	"unconstraineddelegate":       "Accounts with unconstrained delegation",
	"constraineddelegate":         "Accounts with constrained delegation",
	"resourceconstraineddelegate": "Accounts with resource constrained delegation",
	"caComputer":                  "Certificate authorities",
	"esc1":                        "ESC1 vulnerable certificate templates",
	"esc2":                        "ESC2 vulnerable certificate templates",
	"permissions":                 "Account permissions",
	"highpriv":                    "High privilege accounts",
	"group":                       "Admin groups",
	"groupnested":                 "Nested groups",
	"managedby":                   "Objects with managedBy attribute",
	"acl":                         "Objects with ACLs",
	"sidhistory":                  "Accounts with SID history",
	"trustDomain":                 "Trusted domains",
	"trustattributes":             "Trusted domain attributes",
	"machineAccountQuota":         "Machine account quota for the domain",
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
		description := commandDescriptionMap[name]
		if description == "" {
			description = fmt.Sprintf("Run query: %s", name) // Default description
		}

		// Standard query command creation
		cmd := &cobra.Command{
			Use:     use,
			Aliases: aliases,
			Short:   description,
			Long:    description,
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
		category := commandCategoryMap[queryName]
		if category == "" {
			category = CategoryBasic // Default category
		}

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

// simplifyCommandName generates a simplified command name from the query name
func simplifyCommandName(name string) string {
	// Handle special cases with direct mappings
	switch name {
	case "dc":
		return "DC"
	case "gpo":
		return "GPO"
	case "spn":
		return "SPN"
	case "ou":
		return "OU"
	case "acl":
		return "ACL"

	case "asreproast":
		return "ASRepRoast"
	case "kerberoasting":
		return "Kerberoasting"
	case "adminSDHolder":
		return "AdminSDHolder"
	case "machineAccountQuota":
		return "MachineAccountQuota"
	case "resourceconstraineddelegate":
		return "ResourceConstrainedDelegate"
	case "gpomachine":
		return "GpoMachine"
	case "gpouser":
		return "GpoUser"
	case "trustDomain":
		return "TrustDomain"
	case "trustattributes":
		return "TrustAttributes"
	case "adminholders":
		return "AdminHolders"
	case "domainadmins":
		return "DomainAdmins"
	case "enterpriseadmins":
		return "EnterpriseAdmins"
	case "schemaadmins":
		return "SchemaAdmins"
	case "sensitivegroups":
		return "SensitiveGroups"
	case "constraineddelegate":
		return "ConstrainedDelegate"
	case "unconstraineddelegate":
		return "UnconstrainedDelegate"
	case "cacomputer":
		return "CaComputer"
	case "esc1":
		return "Esc1"
	case "esc2":
		return "Esc2"
	case "groupnested":
		return "GroupNested"
	case "highpriv":
		return "HighPriv"
	case "managedby":
		return "ManagedBy"
	case "sidhistory":
		return "SidHistory"
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

	// Handle camelCase and lowercase names
	result := ""
	for i, r := range name {
		if i == 0 || (i > 0 && isUpper(r)) {
			result += strings.ToUpper(string(r))
		} else {
			result += string(r)
		}
	}

	return result
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
		cmd.Printf("Error: Query '%s' not found\n", queryName)
		return
	}

	// Execute common LDAP query logic
	RunQuery(cmd, q.Filter, q.Attributes)
}
