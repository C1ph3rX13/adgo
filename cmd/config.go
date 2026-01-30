package cmd

import (
	"adgo/analyze"
	"adgo/connect"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// AppConfig application configuration structure
type AppConfig struct {
	LDAP   connect.Config `mapstructure:"ldap"`
	Output string         `mapstructure:"output"`
}

const (
	defaultConfigFileName = "adgo.yaml"
	configTemplateName    = "config"
)

var (
	// cfg global configuration instance
	cfg = AppConfig{}

	// viperApp Viper configuration instance
	viperApp = viper.New()

	// validOutputs valid output format map
	validOutputs = map[string]bool{
		analyze.OutputFormatText: true,
		analyze.OutputFormatJSON: true,
		analyze.OutputFormatCSV:  true,
	}

	// securityMap security mode to string mapping
	securityMap = map[int]string{
		0: "None",
		1: "TLS",
		2: "StartTLS",
		3: "InsecureTLS",
		4: "InsecureStartTLS",
	}
)

// yamlTmpl Default configuration template
var yamlTmpl = `# ADGO Configuration File

# LDAP Connection Configuration
ldap:
  server: "{{.LDAP.Server}}"
  port: {{.LDAP.Port}}
  baseDN: "{{.LDAP.BaseDN}}"
  username: "{{.LDAP.Username}}"
  password: "{{.LDAP.Password}}"
  loginName: "{{.LDAP.LoginName}}"
  security: {{.LDAP.Security}}

# Output Configuration
output: "{{.Output}}"
`

// Config search paths - prioritize current directory
var configSearchPaths = []string{
	".",           // Current directory (highest priority)
	"$HOME/.adgo", // User home directory
	"/etc/adgo",   // System directory
}

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage ADGO configuration",
	Long:  "Manage adgo.yaml configuration file. Configure LDAP connection parameters and default output options.",
}

// initCmd represents the config init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  "Generate adgo.yaml in the current directory.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := Save(); err != nil {
			cmd.Println("Error initializing configuration:", err)
			return
		}
		cmd.Println("Configuration initialized.")
	},
}

// setCmd represents the config set command
var setCmd = &cobra.Command{
	Use:   "set KEY VALUE",
	Short: "Set a configuration value",
	Long:  "Set a value in adgo.yaml, e.g., ldap.server / ldap.baseDN / output.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		// Validate input
		if err := validateConfigSet(key, value); err != nil {
			cmd.Printf("Error: %v\n", err)
			return
		}

		Set(key, value)
		if err := Save(); err != nil {
			cmd.Println("Error saving configuration:", err)
			return
		}
		cmd.Printf("Configuration updated: %s = %s\n", key, value)
	},
}

// showCmd represents the config show command
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the current configuration",
	Long:  "Display the merged configuration from file/flags.",
	Run: func(cmd *cobra.Command, args []string) {
		// Get current configuration
		cfg := Get()

		securityStr := securityMap[int(cfg.LDAP.Security)]

		// Get configuration file path
		configPath := GetConfigPath()

		// Display configuration
		cmd.Println("ADGO Config")

		// Show config file path if it exists
		if configPath != "" {
			cmd.Printf("Config File: %s\n", configPath)
		} else {
			cmd.Println("Config File: (not set)")
		}
		cmd.Println()

		// Show LDAP section
		cmd.Println("LDAP:")
		// Show server with not set indicator if empty
		serverValue := cfg.LDAP.Server
		if serverValue == "" {
			serverValue = "(not set)"
		}
		cmd.Printf("  Server:   %s\n", serverValue)
		cmd.Printf("  Port:     %d\n", cfg.LDAP.Port)
		// Show baseDN with not set indicator if empty
		baseDNValue := cfg.LDAP.BaseDN
		if baseDNValue == "" {
			baseDNValue = "(not set)"
		}
		cmd.Printf("  BaseDN:   %s\n", baseDNValue)
		// Show username with not set indicator if empty
		usernameValue := cfg.LDAP.Username
		if usernameValue == "" {
			usernameValue = "(not set)"
		}
		cmd.Printf("  Username: %s\n", usernameValue)
		cmd.Printf("  Login:    %s\n", cfg.LDAP.LoginName)
		cmd.Printf("  Security: %s (%d)\n", securityStr, cfg.LDAP.Security)
		cmd.Println()

		// Show Output section
		cmd.Println("Output:")
		cmd.Printf("  Format:   %s\n", cfg.Output)
		cmd.Println()
	},
}

// Init initializes configuration
func Init() error {
	// Set default values
	setDefaults()

	// Configure Viper
	viperApp.SetConfigName("adgo")
	viperApp.SetConfigType("yaml")

	// Add configuration file search paths (current directory first)
	for _, path := range configSearchPaths {
		viperApp.AddConfigPath(path)
	}

	// Read configuration file (ignore file not found error)
	if err := viperApp.ReadInConfig(); err != nil {
		if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Parse configuration into struct
	return viperApp.Unmarshal(&cfg)
}

// Get returns current configuration
func Get() AppConfig {
	return cfg
}

// Set sets configuration value
func Set(key string, value interface{}) error {
	viperApp.Set(key, value)
	return viperApp.Unmarshal(&cfg)
}

// Save saves configuration to current directory
func Save() error {
	// Get current configuration
	currentCfg := Get()

	// Create template
	tmpl, err := template.New(configTemplateName).Parse(yamlTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse config template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, currentCfg); err != nil {
		return fmt.Errorf("failed to generate config content: %w", err)
	}

	// Write to current directory
	configPath := GetDefaultConfigPath()
	if err := os.WriteFile(configPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// SaveExample saves example configuration file
func SaveExample(path string) error {
	exampleCfg := AppConfig{
		LDAP: connect.Config{
			Server:    "127.0.0.1",
			Port:      analyze.DefaultLDAPPort,
			BaseDN:    "DC=example,DC=com",
			Username:  "Administrator",
			Password:  "",
			LoginName: analyze.DefaultLoginName,
			Security:  analyze.DefaultLDAPSecurity,
		},
		Output: analyze.DefaultOutputFormat,
	}

	tmpl, err := template.New(configTemplateName).Parse(yamlTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse config template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, exampleCfg); err != nil {
		return fmt.Errorf("failed to generate example config: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write example config: %w", err)
	}

	return nil
}

// Validate validates configuration
func Validate() error {
	if cfg.LDAP.Server == "" {
		return errors.New("LDAP server address is not set")
	}

	if cfg.LDAP.BaseDN == "" {
		return errors.New("LDAP base DN is not set")
	}

	if cfg.LDAP.Username == "" {
		return errors.New("LDAP username is not set")
	}

	if cfg.LDAP.Port < 1 || cfg.LDAP.Port > 65535 {
		return errors.New("LDAP port must be in range 1-65535")
	}

	if cfg.LDAP.Security < 0 || cfg.LDAP.Security > 4 {
		return errors.New("security mode must be between 0 and 4")
	}

	if !validOutputs[cfg.Output] {
		return fmt.Errorf("unsupported output format: %s", cfg.Output)
	}

	return nil
}

// Reload reloads configuration
func Reload() error {
	return viperApp.Unmarshal(&cfg)
}

// GetConfigPath returns current configuration file path
func GetConfigPath() string {
	return viperApp.ConfigFileUsed()
}

// GetDefaultConfigPath returns default config file path in current directory
func GetDefaultConfigPath() string {
	return "adgo.yaml"
}

// GetLDAPConfig returns LDAP configuration
func GetLDAPConfig() connect.Config {
	return cfg.LDAP
}

// GetOutputFormat returns output format
func GetOutputFormat() string {
	return cfg.Output
}

// LoadFromFile loads configuration from specific file
func LoadFromFile(filePath string) error {
	viperApp.SetConfigFile(filePath)
	if err := viperApp.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config from %s: %w", filePath, err)
	}

	return viperApp.Unmarshal(&cfg)
}

// ResetToDefaults resets configuration to default values
func ResetToDefaults() error {
	// Reset Viper to defaults
	setDefaults()

	// Parse configuration into struct
	return viperApp.Unmarshal(&cfg)
}

// bindFlag helper to bind a flag to a viper key
func bindFlag(cmd *cobra.Command, flagName, viperKey, usage string, defaultValue interface{}) {
	switch v := defaultValue.(type) {
	case string:
		cmd.PersistentFlags().String(flagName, v, usage)
	case int:
		cmd.PersistentFlags().Int(flagName, v, usage)
	}
	viperApp.BindPFlag(viperKey, cmd.PersistentFlags().Lookup(flagName))
}

// BindFlags binds command line flags to configuration
func BindFlags(cmd *cobra.Command) {
	viperApp.BindPFlag(analyze.ConfigLDAPServer, cmd.PersistentFlags().Lookup("server"))
	viperApp.BindPFlag(analyze.ConfigLDAPPort, cmd.PersistentFlags().Lookup("port"))
	viperApp.BindPFlag(analyze.ConfigLDAPBaseDN, cmd.PersistentFlags().Lookup("baseDN"))
	viperApp.BindPFlag(analyze.ConfigLDAPUsername, cmd.PersistentFlags().Lookup("username"))
	viperApp.BindPFlag(analyze.ConfigLDAPPassword, cmd.PersistentFlags().Lookup("password"))

	if cmd.PersistentFlags().Lookup("login-name") == nil {
		bindFlag(cmd, "login-name", analyze.ConfigLDAPLoginName, "Login name format (userPrincipalName or sAMAccountName)", analyze.DefaultLoginName)
	} else {
		viperApp.BindPFlag(analyze.ConfigLDAPLoginName, cmd.PersistentFlags().Lookup("login-name"))
	}

	if cmd.PersistentFlags().Lookup("security") == nil {
		bindFlag(cmd, "security", analyze.ConfigLDAPSecurity, "Security mode (0=None, 1=TLS, 2=StartTLS, 3=InsecureTLS, 4=InsecureStartTLS)", analyze.DefaultLDAPSecurity)
	} else {
		viperApp.BindPFlag(analyze.ConfigLDAPSecurity, cmd.PersistentFlags().Lookup("security"))
	}

	viperApp.BindPFlag(analyze.ConfigOutput, cmd.PersistentFlags().Lookup("output"))
}

// validateConfigSet validates the key-value pair for config set command
func validateConfigSet(key, value string) error {
	switch key {
	case analyze.ConfigLDAPPort:
		p, err := strconv.Atoi(value)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: must be between 1-65535")
		}
	case analyze.ConfigLDAPBaseDN:
		if !strings.Contains(strings.ToUpper(value), "DC=") {
			return fmt.Errorf("base DN usually contains 'DC=' components")
		}
	case analyze.ConfigLDAPSecurity:
		s, err := strconv.Atoi(value)
		if err != nil || s < 0 || s > 4 {
			return fmt.Errorf("invalid security mode: must be 0-4")
		}
	case analyze.ConfigOutput:
		if !validOutputs[value] {
			return fmt.Errorf("invalid output format: must be text, json, or csv")
		}
	}
	return nil
}

// Internal functions

func setDefaults() {
	// LDAP defaults
	viperApp.SetDefault(analyze.ConfigLDAPServer, "")
	viperApp.SetDefault(analyze.ConfigLDAPPort, analyze.DefaultLDAPPort)
	viperApp.SetDefault(analyze.ConfigLDAPBaseDN, "")
	viperApp.SetDefault(analyze.ConfigLDAPUsername, "")
	viperApp.SetDefault(analyze.ConfigLDAPPassword, "")
	viperApp.SetDefault(analyze.ConfigLDAPLoginName, analyze.DefaultLoginName)
	viperApp.SetDefault(analyze.ConfigLDAPSecurity, analyze.DefaultLDAPSecurity)

	// Output defaults
	viperApp.SetDefault(analyze.ConfigOutput, analyze.DefaultOutputFormat)
}

func init() {
	rootCmd.AddCommand(configCmd)

	// Add config subcommands here
	configCmd.AddCommand(initCmd)
	configCmd.AddCommand(setCmd)
	configCmd.AddCommand(showCmd)
}
