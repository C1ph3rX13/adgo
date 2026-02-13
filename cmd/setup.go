package cmd

import (
	"adgo/analyze"
	"adgo/log"
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// setup runs the interactive configuration wizard
func setup() {
	log.Info("No configuration file found and missing required flags")
	log.Info("Starting interactive setup wizard")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	// required validates that input is not empty
	required := func(input string) error {
		if strings.TrimSpace(input) == "" {
			return fmt.Errorf("cannot be empty")
		}
		return nil
	}

	// Get current config
	currentCfg := GetConfig()

	// Server
	currentCfg.LDAP.Server = prompt(scanner, "Domain Controller Host/IP: ", required, false)

	// Port
	port := analyze.DefaultLDAPPort
	s := prompt(scanner, fmt.Sprintf("LDAP Port [%d]: ", port), func(input string) error {
		if input == "" {
			return nil
		}
		p, err := strconv.Atoi(input)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: must be between 1-65535")
		}
		return nil
	}, false)
	if s != "" {
		currentCfg.LDAP.Port, _ = strconv.Atoi(s)
	} else {
		currentCfg.LDAP.Port = port
	}

	// BaseDN
	currentCfg.LDAP.BaseDN = prompt(scanner, "Base DN (e.g., DC=sec,DC=lab): ", func(input string) error {
		if err := required(input); err != nil {
			return err
		}
		if !strings.Contains(strings.ToUpper(input), "DC=") {
			return fmt.Errorf("base DN usually contains 'DC=' components")
		}
		return nil
	}, false)

	// Username
	currentCfg.LDAP.Username = prompt(scanner, "Username: ", required, false)

	// Password
	currentCfg.LDAP.Password = prompt(scanner, "Password: ", nil, true)

	// Save option
	save := prompt(scanner, "Save this configuration for future use? [Y/n]: ", nil, false)
	if save == "" || strings.ToLower(save) == "y" || strings.ToLower(save) == "yes" {
		// Set the config values
		_ = SetConfig(analyze.ConfigLDAPServer, currentCfg.LDAP.Server)
		_ = SetConfig(analyze.ConfigLDAPPort, currentCfg.LDAP.Port)
		_ = SetConfig(analyze.ConfigLDAPBaseDN, currentCfg.LDAP.BaseDN)
		_ = SetConfig(analyze.ConfigLDAPUsername, currentCfg.LDAP.Username)
		_ = SetConfig(analyze.ConfigLDAPPassword, currentCfg.LDAP.Password)

		if err := SaveConfig(); err != nil {
			log.Errorf("saving configuration: %v", err)
		} else {
			log.Infof("Configuration saved to %s", DefaultConfigPath())
		}
	}

	fmt.Println()
	log.Info("Setup complete. Running command...")
	fmt.Println()
}

// prompt helper for user input
func prompt(scanner *bufio.Scanner, label string, validator func(string) error, isPassword bool) string {
	if isPassword {
		fmt.Print(label)
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return ""
		}
		password := string(bytePassword)
		if validator != nil {
			if err := validator(password); err != nil {
				log.Warn(err.Error())
				return prompt(scanner, label, validator, isPassword)
			}
		}
		return password
	}

	for {
		fmt.Print(label)
		if !scanner.Scan() {
			return ""
		}
		input := strings.TrimSpace(scanner.Text())

		if validator != nil {
			if err := validator(input); err != nil {
				log.Warn(err.Error())
				continue
			}
		}
		return input
	}
}
