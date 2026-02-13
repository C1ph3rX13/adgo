package cmd

import (
	"adgo/analyze"
	"adgo/connect"
	"adgo/log"
	"bytes"
	"errors"
	"fmt"
	"os"
	"text/template"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// cfgManager is the global configuration manager instance
	cfgManager *Manager
)

// AppConfig application configuration structure
type AppConfig struct {
	LDAP   connect.Config `mapstructure:"ldap"`
	Output string         `mapstructure:"output"`
}

// Manager handles configuration loading, saving, and access in a thread-safe manner
type Manager struct {
	viper *viper.Viper
	cfg   AppConfig
	mu    sync.RWMutex
}

// NewManager creates a new configuration manager
func NewManager() *Manager {
	return &Manager{
		viper: viper.New(),
		cfg:   AppConfig{},
	}
}

const (
	defaultConfigFileName = "adgo.yaml"
	configTemplateName    = "config"
)

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

// configSearchPaths defines where to look for configuration files
var configSearchPaths = []string{
	".",           // Current directory (highest priority)
	"$HOME/.adgo", // User home directory
	"/etc/adgo",   // System directory
}

// DefaultConfigPath returns the default configuration file path
func DefaultConfigPath() string {
	return "adgo.yaml"
}

// saveConfigToFile generates config content and writes to file
func saveConfigToFile(cfg AppConfig, path string, perm os.FileMode) error {
	content, err := generateConfigContent(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, content, perm); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

// generateConfigContent generates configuration content from template
func generateConfigContent(cfg AppConfig) ([]byte, error) {
	tmpl, err := template.New(configTemplateName).Parse(yamlTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return nil, fmt.Errorf("failed to generate config content: %w", err)
	}

	return buf.Bytes(), nil
}

// Manager methods

// Init initializes the configuration by setting defaults and reading the config file
// from search paths (current directory, ~/.adgo, /etc/adgo). Returns an error if
// the config file exists but cannot be read.
func (m *Manager) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Set default values
	m.setDefaults()

	// Configure Viper
	m.viper.SetConfigName("adgo")
	m.viper.SetConfigType("yaml")

	// Add configuration file search paths (current directory first)
	for _, path := range configSearchPaths {
		m.viper.AddConfigPath(path)
	}

	// Read configuration file (ignore file not found error)
	if err := m.viper.ReadInConfig(); err != nil {
		if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Parse configuration into struct
	return m.viper.Unmarshal(&m.cfg)
}

// Get returns the current application configuration
func (m *Manager) Get() AppConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// Set sets a configuration value by key and updates the internal config struct
func (m *Manager) Set(key string, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.viper.Set(key, value)
	return m.viper.Unmarshal(&m.cfg)
}

// Save saves the current configuration to adgo.yaml in the current directory
// with file permissions 0600 (read/write for owner only).
func (m *Manager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return saveConfigToFile(m.cfg, DefaultConfigPath(), 0600)
}

// SaveExample saves an example configuration file with placeholder values
// to the specified path with file permissions 0644.
func (m *Manager) SaveExample(path string) error {
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
	return saveConfigToFile(exampleCfg, path, 0644)
}

// Validate validates the current configuration, checking that all required fields
// are set and values are within acceptable ranges. Returns an error describing
// the first validation failure.
func (m *Manager) Validate() error {
	cfg := m.Get()

	if cfg.LDAP.Server == "" {
		return errors.New("LDAP server is not configured")
	}

	if cfg.LDAP.BaseDN == "" {
		return errors.New("LDAP base DN is not set")
	}

	if cfg.LDAP.Username == "" {
		return errors.New("LDAP username is not set")
	}

	if cfg.LDAP.Port < analyze.MinPort || cfg.LDAP.Port > analyze.MaxPort {
		return fmt.Errorf("LDAP port must be between %d and %d", analyze.MinPort, analyze.MaxPort)
	}

	if !analyze.IsValidSecurityMode(int(cfg.LDAP.Security)) {
		return fmt.Errorf("LDAP security mode must be between %d and %d",
			analyze.SecurityModeNone, analyze.SecurityModeInsecureStartTLS)
	}

	return nil
}

// Reload reloads the configuration from viper, updating the internal config struct
func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viper.Unmarshal(&m.cfg)
}

// ConfigPath returns the path to the configuration file that was loaded, or an
// empty string if no config file was found.
func (m *Manager) ConfigPath() string {
	return m.viper.ConfigFileUsed()
}

// LDAPConfig returns the LDAP connection configuration
func (m *Manager) LDAPConfig() connect.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.LDAP
}

// OutputFormat returns the configured output format
func (m *Manager) OutputFormat() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Output
}

// BindFlag binds a command line flag to a viper configuration key
func (m *Manager) BindFlag(key string, flag interface{}) error {
	// This method is kept for compatibility but not used in current implementation
	return nil
}

// setDefaults sets default values for configuration
func (m *Manager) setDefaults() {
	// LDAP defaults
	m.viper.SetDefault(analyze.ConfigLDAPServer, "")
	m.viper.SetDefault(analyze.ConfigLDAPPort, analyze.DefaultLDAPPort)
	m.viper.SetDefault(analyze.ConfigLDAPBaseDN, "")
	m.viper.SetDefault(analyze.ConfigLDAPUsername, "")
	m.viper.SetDefault(analyze.ConfigLDAPPassword, "")
	m.viper.SetDefault(analyze.ConfigLDAPLoginName, analyze.DefaultLoginName)
	m.viper.SetDefault(analyze.ConfigLDAPSecurity, analyze.DefaultLDAPSecurity)

	// Output defaults
	m.viper.SetDefault(analyze.ConfigOutput, analyze.DefaultOutputFormat)
}

// Cobra Commands

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
		if err := SaveConfig(); err != nil {
			log.Errorf("Initializing configuration: %v", err)
			return
		}
		log.Info("Configuration initialized")
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
			log.Error(err.Error())
			return
		}

		if err := SetConfig(key, value); err != nil {
			log.Errorf("Setting %s: %v", key, err)
			return
		}

		if err := SaveConfig(); err != nil {
			log.Errorf("Saving configuration: %v", err)
			return
		}
		log.Infof("Configuration updated: %s = %s", key, value)
	},
}

// showCmd represents the config show command
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the current configuration",
	Long:  "Display the merged configuration from file/flags.",
	Run: func(cmd *cobra.Command, args []string) {
		// Get current configuration
		c := GetConfig()

		// Get configuration file path
		path := GetConfigPath()

		// Display configuration
		cmd.Println("ADGO Config")

		// Show config file path if it exists
		if path != "" {
			cmd.Printf("Config File: %s\n", path)
		} else {
			cmd.Println("Config File: (not set)")
		}
		cmd.Println()

		// Show LDAP section
		cmd.Println("LDAP:")
		cmd.Printf("  Server:   %s\n", valueOrNotSet(c.LDAP.Server))
		cmd.Printf("  Port:     %d\n", c.LDAP.Port)
		cmd.Printf("  BaseDN:   %s\n", valueOrNotSet(c.LDAP.BaseDN))
		cmd.Printf("  Username: %s\n", valueOrNotSet(c.LDAP.Username))
		cmd.Printf("  Login:    %s\n", c.LDAP.LoginName)
		securityName, _ := analyze.SecurityModeName(int(c.LDAP.Security))
		cmd.Printf("  Security: %s (%d)\n", securityName, c.LDAP.Security)
		cmd.Println()

		// Show Output section
		cmd.Println("Output:")
		cmd.Printf("  Format:   %s\n", c.Output)
		cmd.Println()
	},
}

// Package-level API functions

// InitConfig initializes the configuration by setting defaults and reading the config file
// from search paths (current directory, ~/.adgo, /etc/adgo). Returns an error if
// the config file exists but cannot be read.
func InitConfig() error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.Init()
}

// GetConfig returns the current application configuration.
func GetConfig() AppConfig {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.Get()
}

// SetConfig sets a configuration value by key and updates the internal config struct.
// The key should be a dot-separated path (e.g., "ldap.server").
func SetConfig(key string, value interface{}) error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.Set(key, value)
}

// SaveConfig saves the current configuration to adgo.yaml in the current directory
// with file permissions 0600 (read/write for owner only).
func SaveConfig() error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.Save()
}

// SaveExample saves an example configuration file with placeholder values
// to the specified path with file permissions 0644.
func SaveExample(path string) error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.SaveExample(path)
}

// Validate validates the current configuration, checking that all required fields
// are set and values are within acceptable ranges. Returns an error describing
// the first validation failure.
func Validate() error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.Validate()
}

// valueOrNotSet returns value or "(not set)" if empty
func valueOrNotSet(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

// Reload reloads the configuration from viper, updating the internal config struct
// with the latest values from viper's merged state (Flags > Env > Config > Defaults).
func Reload() error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.Reload()
}

// GetConfigPath returns the path to the configuration file that was loaded, or an
// empty string if no config file was found.
func GetConfigPath() string {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.ConfigPath()
}

// LDAPConfig returns the LDAP connection configuration.
func LDAPConfig() connect.Config {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.LDAPConfig()
}

// OutputFormat returns the configured output format (text, json, or csv).
func OutputFormat() string {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	return cfgManager.OutputFormat()
}

// LoadFromFile loads configuration from a specific file path, overriding
// the default search behavior.
func LoadFromFile(filePath string) error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	// For now, this would require extending the Manager interface
	return fmt.Errorf("LoadFromFile not yet implemented with ConfigManager")
}

// ResetToDefaults resets all configuration values to their defaults and
// updates the internal config struct.
func ResetToDefaults() error {
	if cfgManager == nil {
		cfgManager = NewManager()
	}
	// Re-initialize to reset to defaults
	return cfgManager.Init()
}

// bindFlag helper to bind a flag to a viper key
func bindFlag(cmd *cobra.Command, flagName, viperKey, usage string, defaultValue interface{}) error {
	switch val := defaultValue.(type) {
	case string:
		cmd.PersistentFlags().String(flagName, val, usage)
	case int:
		cmd.PersistentFlags().Int(flagName, val, usage)
	}
	// Note: This uses the global viper for backward compatibility
	// In a future refactor, this would use cfgManager.BindFlag
	return viper.BindPFlag(viperKey, cmd.PersistentFlags().Lookup(flagName))
}

// BindFlags binds command line flags to viper configuration keys, allowing
// flag values to override configuration file values.
func BindFlags(cmd *cobra.Command) {
	// Note: This uses the global viper for backward compatibility
	// In a future refactor, this would be updated to use cfgManager
	v := viper.New()

	v.BindPFlag(analyze.ConfigLDAPServer, cmd.PersistentFlags().Lookup("server"))
	v.BindPFlag(analyze.ConfigLDAPPort, cmd.PersistentFlags().Lookup("port"))
	v.BindPFlag(analyze.ConfigLDAPBaseDN, cmd.PersistentFlags().Lookup("baseDN"))
	v.BindPFlag(analyze.ConfigLDAPUsername, cmd.PersistentFlags().Lookup("username"))
	v.BindPFlag(analyze.ConfigLDAPPassword, cmd.PersistentFlags().Lookup("password"))

	if cmd.PersistentFlags().Lookup("login-name") == nil {
		bindFlag(cmd, "login-name", analyze.ConfigLDAPLoginName, "Login name format (userPrincipalName or sAMAccountName)", analyze.DefaultLoginName)
	} else {
		v.BindPFlag(analyze.ConfigLDAPLoginName, cmd.PersistentFlags().Lookup("login-name"))
	}

	if cmd.PersistentFlags().Lookup("security") == nil {
		bindFlag(cmd, "security", analyze.ConfigLDAPSecurity,
			fmt.Sprintf("Security mode (%d=None, %d=TLS, %d=StartTLS, %d=InsecureTLS, %d=InsecureStartTLS)",
				analyze.SecurityModeNone,
				analyze.SecurityModeTLS,
				analyze.SecurityModeStartTLS,
				analyze.SecurityModeInsecureTLS,
				analyze.SecurityModeInsecureStartTLS),
			analyze.DefaultLDAPSecurity)
	} else {
		v.BindPFlag(analyze.ConfigLDAPSecurity, cmd.PersistentFlags().Lookup("security"))
	}

	v.BindPFlag(analyze.ConfigOutput, cmd.PersistentFlags().Lookup("output"))
}

// validateConfigSet validates the key-value pair for config set command
func validateConfigSet(key, value string) error {
	switch key {
	case analyze.ConfigLDAPPort:
		return ValidatePortString(value)
	case analyze.ConfigLDAPBaseDN:
		return ValidateBaseDN(value)
	case analyze.ConfigLDAPSecurity:
		return ValidateSecurityModeString(value)
	case analyze.ConfigOutput:
		return ValidateOutputFormat(value)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(configCmd)

	// Add config subcommands here
	configCmd.AddCommand(initCmd)
	configCmd.AddCommand(setCmd)
	configCmd.AddCommand(showCmd)
}
